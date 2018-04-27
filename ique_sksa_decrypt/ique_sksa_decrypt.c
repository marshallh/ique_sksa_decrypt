//
// ique_sksa_decrypt 0.2
// 2018 marshallh
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"
#include "sha1.h"

// little endian host platform is assumed, nop this if you're big endian
#define BYTESWAP_32(x)  ((x >> 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x << 24))

void decrypt_sk(char *infilename, char *outfilename, uint8_t *skey, uint8_t *siv);
void decrypt_sa(char *infilename, char *outfilename, uint8_t *ckey, struct cmd *sa_cmd, unsigned char *sa_hash, int offset);
void die(char *reason);
int parse_hex_to_char(char *inp, char *outp, int len);
void print_key(char *msg, uint8_t *key);
void print_hash(char *msg, uint8_t *hash);


// struct from SUXXORS release nfo
// not mine, comments are from the nfo
struct cmd {                                                          
	//uint8_t opaque_data;		//[ ( is_secure_app ? 0 : 10240 ) ]      
	uint32_t padding;                                                   
	uint32_t ca_crl_version;                                            
	uint32_t cmd_crl_version;                                           
	uint32_t content_size;                                              
	uint32_t unused_flags;		// bit 0 on if SA; nothing checks it though  
	uint8_t titlekey_iv[0x10];	/* iv used to encrypt titlekey (with     
									common key) */                                      
	uint8_t content_hash[0x14]; // sha1 hash of plaintext content       
	uint8_t content_iv[0x10];	// iv used to encrypt content             
	uint32_t recrypt_flag;		/* if bit 1 on, content will be re-encrypted 
								 * on first launch, using console-unique key 
								 * stored in OTP in the SoC                  
								 */                                          
	uint32_t allowed_hardware; /* bitfield, each bit enables access to  
								* some MMIO regs new to iQue Player:    
								* bits 0-7: new PI stuff                
								* bit 0: PI buffer used for aes/NAND    
								*        read output and PI DMA         
								*        (1KB at PI_BASE+0x10000)       
								* bit 1: NAND flash regs in PI          
								* bit 2: memory mapper for old PI dma   
								* bit 3: hardware AES-engine in PI      
								* bit 4: new PI dma engine, DMAs        
								*        from/to PI buffer              
								* bit 5: new GPIO; power + LED          
								* bit 6: external IO bus stuff (debug?) 
								* bit 7: new PI error stuff             
								*                                       
								* bit 8: enables access to USB regs     
								* bit 9: enables access to internal     
								*        ram used for SK stack          
								*/                                      
	uint32_t allowed_secure_kernel_calls; /* one bit per syscall        
											* bit 0 allows skc 0, etc.   
											*/                           
	uint32_t console_id;	/* can be zero; if not can only run on certain 
							 * console (used for SAs, not games)           
							 */                                            
	uint8_t signer[64];		// certificate used to sign the cmd             
	uint32_t content_id;                                                
	uint8_t titlekey[0x10]; /* crypted with common key, and if this is  
							 * not an SA, then crypted again with key   
							 * derived using ECDH of console's privkey  
							 * and pubkey in ticket                     
							 */                                         
	uint8_t signature[0x100]; // RSA-2048 sig on all above elements     
};

int verbose = 0;
                         
int main(int argc, char* argv[])
{
	int ca;

	uint8_t key_common[16] = { 0, };
	uint8_t key_sk_key[16] = { 0, };
	uint8_t key_sk_iv[16] = { 0, };
	uint8_t key_empty[16] = { 0, };
	char filename[256] = { 0, };
	char filename_sk[256] = { 0, };
	char filename_sa1[256] = { 0, };
	char filename_sa2[256] = { 0, };

	uint32_t sa_size[2] = { 0, };
	unsigned char sa_hash[20][2] = { 0, };
	struct cmd sa_cmd[2] = { 0, };

	printf("ique_sksa_decrypt 0.2 by marshallh\n");
	printf("----------------------------------\n");
	if (argc == 1){
		printf("Arguments: ique_sksa_decrypt\n");
		printf("\t -f <sksa_in_file_name>\n");
		printf("\t[-skout <sk_out filename>]\n");
		printf("\t[-sa1out <sa1_out filename>]\n");
		printf("\t[-sa2out <sa2_out filename>]\n");
		printf("\t[-ckey <common_key>]\n");
		printf("\t[-skey <sk_key>]\n");
		printf("\t[-siv <sk_iv>]\n");
		printf("\t[-v] (enables verbose printing of values)\n");
		printf("You may either choose to extract SK, SA1, or SA1+SA2.\n");
		printf("Specifying a filename means you want to extract it.\n");
		printf("Extracting SK requires skey/siv, extracting SA1/2 requires ckey.\n");
	}
	
	for (ca = 1; ca < argc; ca++){
		if (!strcmp(argv[ca], "-f")) {
			if (++ca < argc ) sscanf(argv[ca], "%s", filename);
			else {printf("No filename specified"); return -1;}
		} else if (!strcmp(argv[ca], "-skout")) {
			if (++ca < argc) sscanf(argv[ca], "%s", filename_sk);
			else {printf("No sk out filename specified"); return -1;}
		} else if (!strcmp(argv[ca], "-sa1out")) {
			if (++ca < argc) sscanf(argv[ca], "%s", filename_sa1);
			else printf("No sa1 out filename specified"); 
		} else if (!strcmp(argv[ca], "-sa2out")) {
			if (++ca < argc) sscanf(argv[ca], "%s", filename_sa2);
			else printf("No sa2 out filename specified"); 
		} else if (!strcmp(argv[ca], "-ckey") ){
			if (++ca < argc) parse_hex_to_char(argv[ca], key_common, 16);
			else printf("Invalid/missing commonkey");
		} else if (!strcmp(argv[ca], "-skey")) {
			if (++ca < argc) parse_hex_to_char(argv[ca], key_sk_key, 16);
			else printf("Invalid/missing sk_key");
		} else if (!strcmp(argv[ca], "-siv")) {
			if (++ca < argc) parse_hex_to_char(argv[ca], key_sk_iv, 16);
			else printf("Invalid/missing sk_iv");
		} else if(!strcmp(argv[ca], "-v")) {
			verbose = 1;
		}
	}
	if (filename[0] == 0) die("No filename specified");

	printf("* Opening SKSA binary %s\n", filename);

	if (filename_sk[0] != 0){
		printf("* Decrypting SK to file %s\n", filename_sk);
		if (memcmp(key_empty, key_sk_key, 16) == 0) die("Missing SK Key");
		if (memcmp(key_empty, key_sk_iv, 16) == 0) die("Missing SK IV");
		decrypt_sk(filename, filename_sk, key_sk_key, key_sk_iv);
	}

	if (filename_sa1[0] != 0){
		printf("* Decrypting SA1 to file %s\n", filename_sa1);
		if (memcmp(key_empty, key_common, 16) == 0) die("Missing common key");
		printf("* SA1:\n");
		decrypt_sa(filename, filename_sa1, key_common, &sa_cmd[0], &sa_hash[0][0], 0x10000);
	}

	if (filename_sa2[0] != 0){
		printf("* Decrypting SA2 to file %s\n", filename_sa2);
		if (filename_sa2[0] == 0) die("You must extract SA1 as well if you want SA2");
		if (memcmp(key_empty, key_common, 16) == 0) die("Missing common key");
		printf("* SA2:\n");
		decrypt_sa(filename, filename_sa2, key_common, &sa_cmd[1], &sa_hash[0][1], 0x14000 + BYTESWAP_32(sa_cmd[0].content_size));
	}

	printf("* Done\n");
	return 0;
}

void decrypt_sk(char *infilename, char *outfilename, uint8_t *skey, uint8_t *siv)
{
	uint8_t *buf = NULL;
	FILE *fp;
	FILE *fp_out;
	struct AES_ctx ctx;

	fp = fopen(infilename, "rb"); if (fp == NULL) die("Couldn't open inputfile");
	buf = malloc(65536); if (buf == NULL) die("Couldn't malloc SK");

	fread(buf, 1, 65536, fp);
	AES_init_ctx_iv(&ctx, skey, siv);
	AES_CBC_decrypt_buffer(&ctx, buf, 65536);
	fp_out = fopen(outfilename, "wb");
	fwrite(buf, 1, 65536, fp_out);
	fclose(fp_out);

	fclose(fp);
	if(buf != NULL) free(buf);
}

void decrypt_sa(char *infilename, char *outfilename, uint8_t *ckey, struct cmd *sa_cmd, unsigned char *sa_hash, int offset)
{
	uint8_t *sa_data = NULL;
	FILE *fp;
	FILE *fp_out;
	struct AES_ctx ctx;
	int sa_size;
	uint8_t header_expected[4] = { 0x80, 0x37, 0x12, 0x40 };

	fp = fopen(infilename, "rb"); if (fp == NULL) die("Couldn't open inputfile");
	fseek(fp, offset, SEEK_SET);
	fread(sa_cmd, sizeof(struct cmd), 1, fp);
	// please note while we've read in the data, all fields are wrong-endian so we must 
	// take care to endian swap any data we want to read from the struct
	sa_size = BYTESWAP_32(sa_cmd->content_size);
	printf("SA is %d/0x%X bytes\n", sa_size, sa_size);
	printf("SA is content ID %d\n", BYTESWAP_32(sa_cmd->content_id));
	if (sa_size % 16 != 0) die("SA size is not a modulus of 16, something is very wrong");
	if (sa_size == 0) {
		printf("SA doesn't exist, skipping\n");
		goto bail;
	}
	sa_data = malloc(sa_size); if (sa_data == NULL) die("Couldn't malloc SA");

	fseek(fp, offset + 0x4000, SEEK_SET);
	fread(sa_data, sa_size, 1, fp);

	printf("SA signer is %s\n", sa_cmd->signer);
	print_hash("SA content hash is", sa_cmd->content_hash);
	print_key("SA titlekey_iv is", sa_cmd->titlekey_iv);
	print_key("SA content_iv is", sa_cmd->content_iv);
	print_key("SA titlekey(crypted) is", sa_cmd->titlekey);
	// first, decrypt the SA's titlekey with common key
	AES_init_ctx_iv(&ctx, ckey, sa_cmd->titlekey_iv);
	AES_CBC_decrypt_buffer(&ctx, sa_cmd->titlekey, 16);
	print_key("SA titlekey(decrypted) is", sa_cmd->titlekey);
	// now use decrypted titlekey to decrypt the payload
	AES_init_ctx_iv(&ctx, sa_cmd->titlekey, sa_cmd->content_iv);
	AES_CBC_decrypt_buffer(&ctx, sa_data, sa_size);

	sha1_buffer(sa_data, sa_size, sa_hash);
	print_hash("SA computed hash is", sa_hash);
	if (memcmp(sa_hash, sa_cmd->content_hash, 20) == 0)
		printf("SA content hash matches internal hash\n");
	else
		printf("SA content has does NOT match\n");

	// write decrypted to file
	fp_out = fopen(outfilename, "wb");
	fwrite(sa_data, 1, sa_size, fp_out);
	fclose(fp_out);
	if (memcmp(header_expected, sa_data, 4) != 0) printf("Extracted SA1 contains some type of metadata, FYI.\n");
bail:
	fclose(fp);
	if(sa_data != NULL) free(sa_data);
}


void die(char *reason)
{
	printf("\nDIE: %s, exiting\n", reason);
	exit(-1);
}

int parse_hex_to_char(char *inp, char *outp, int len)
{
	char *src = inp;
	char *dst = outp;
	char *end = outp + len;
	unsigned int u;

	while (dst < end && sscanf(src, "%2x", &u) == 1){
		*dst++ = u;
		src += 2;
	}
	return 0;
}

void print_key(char *msg, uint8_t *key)
{
	if (!verbose) return;
	printf("%s ", msg);
	for (int k = 0; k <16; k++) { 
		printf("%02X", key[k]);
	} 
	printf("\n");
}

void print_hash(char *msg, uint8_t *hash)
{
	if (!verbose) return;
	printf("%s ", msg);
	for (int k = 0; k < 20; k++) {
		printf("%02X", hash[k]);
	}
	printf("\n");
}


