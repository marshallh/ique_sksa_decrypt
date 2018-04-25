//
// ique_sksa_decrypt 0.1
// 2018 marshallh
//

#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "sha1.h"

#define BYTESWAP_32(x)  ((x >> 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x << 24))

void die(char *reason);
int parse_hex_to_char(char *inp, char *outp, int len);
void print_key(char *msg, unsigned char *key);
void print_hash(char *msg, unsigned char *hash);


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
	int i;
	
	FILE *fp;
	FILE *fp_out;

	char key_common[16] = { 0, };
	char key_sk_key[16] = { 0, };
	char key_sk_iv[16] = { 0, };
	char filename[256] = { 0, };
	char filename_sk[256] = { 0, };
	char filename_sa1[256] = { 0, };
	char filename_sa2[256] = { 0, };

	char key_empty[16] = {0, };
	unsigned char *sk_data = NULL;
	unsigned char *sa1_data = NULL;
	unsigned char *sa2_data = NULL;

	uint32_t sa1_size = 0;
	uint32_t sa2_size = 0;

	struct cmd sa1_cmd = { 0,  };
	struct cmd sa2_cmd = { 0, };
	struct AES_ctx ctx;
	struct sha1_ctx sha;

	unsigned char sa1_hash[20] = { 0, };
	unsigned char sa2_hash[20] = { 0, };

	uint8_t header_expected[4] = {0x80, 0x37, 0x12, 0x40};

	printf("ique_sksa_decrypt 0.1 by marshallh\n");
	printf("----------------------------------\n");
	if (argc == 1){
		printf("Arguments: ique_sksa_decrypt\n");
		printf("\t -f <sksa_in_file_name>\n");
		printf("\t[-skout <sk_out filename>]\n");
		printf("\t[-sa1out <sa1_out filename>]\n");
		printf("\t[-sa2out <sa2_out filename>]\n");
		printf("\t -ckey <common_key>\n");
		printf("\t -skey <sk_key>\n");
		printf("\t -siv <sk_iv>\n");
		printf("\t -v (enables verbose printing of values)\n");
		printf("You may either choose to extract SK, SA1, or SA1+SA2.\n");
		printf("Specifying a filename means you want to extract it.\n");
	}


	for (ca = 1; ca < argc; ca++){
		if (!strcmp(argv[ca], "-f")){
			if (++ca < argc ){
				sscanf(argv[ca], "%s", filename);
			} else {
				printf("No filename specified"); return -1;
			}
		} else if (!strcmp(argv[ca], "-skout")){
			if (++ca < argc){
				sscanf(argv[ca], "%s", filename_sk);
			}
			else {
				printf("No sk out filename specified"); return -1;
			}
		} else if (!strcmp(argv[ca], "-sa1out")){
			if (++ca < argc){
				sscanf(argv[ca], "%s", filename_sa1);
			}
			else {
				printf("No sa1 out filename specified"); 
			}
		} else if (!strcmp(argv[ca], "-sa2out")){
			if (++ca < argc){
				sscanf(argv[ca], "%s", filename_sa2);
			}
			else {
				printf("No sa2 out filename specified"); 
			}
		}
		else if (!strcmp(argv[ca], "-ckey")){
			if (++ca < argc){
				parse_hex_to_char(argv[ca], key_common, 16);
			}
			else {
				printf("Invalid/missing commonkey");
			}
		} else if (!strcmp(argv[ca], "-skey")){
			if (++ca < argc){
				parse_hex_to_char(argv[ca], key_sk_key, 16);
			}
			else {
				printf("Invalid/missing sk_key");
			}
		} else if (!strcmp(argv[ca], "-siv")){
			if (++ca < argc){
				parse_hex_to_char(argv[ca], key_sk_iv, 16);
			}
			else {
				printf("Invalid/missing sk_iv");
			}
		}
		else if(!strcmp(argv[ca], "-v")){
			verbose = 1;
		}
	}

	if (filename[0] == 0) die("No filename specified");

	printf("* Opening SKSA binary %s\n", filename);
	fp = fopen(filename, "rb");
	if (fp == NULL) die("Couldn't open file");

	if (filename_sk[0] != 0){
		printf("* Decrypting SK to file %s\n", filename_sk);
		if (memcmp(key_empty, key_sk_key, 16) == 0) die("Missing SK Key");
		if (memcmp(key_empty, key_sk_iv, 16) == 0) die("Missing SK IV");
		sk_data = malloc(65536); if (sk_data == NULL) die("Couldn't malloc SK");
		fread(sk_data, 1, 65536, fp);
		AES_init_ctx_iv(&ctx, key_sk_key, key_sk_iv);
		AES_CBC_decrypt_buffer(&ctx, sk_data, 65536);
		fp_out = fopen(filename_sk, "wb");
		fwrite(sk_data, 1, 65536, fp_out);
		fclose(fp_out);
	}

	if (filename_sa1[0] != 0){
		printf("* Decrypting SA1 to file %s\n", filename_sa1);
		if (memcmp(key_empty, key_common, 16) == 0) die("Missing common key");
		fseek(fp, 0x10000, SEEK_SET);
		fread(&sa1_cmd, sizeof(struct cmd), 1, fp);
		// please note while we've read in the data, all fields are wrong-endian so we must 
		// take care to endian swap any data we want to read from the struct
		sa1_size = BYTESWAP_32(sa1_cmd.content_size);
		printf("SA1 is %d/0x%X bytes\n", sa1_size, sa1_size);
		printf("SA1 is content ID %d\n", BYTESWAP_32(sa1_cmd.content_id));
		if (sa1_size % 16 != 0) die("SA1 size is not a modulus of 16, something is very wrong");
		sa1_data = malloc(sa1_size); if (sa1_size == NULL) die("Couldn't malloc SA1");
		fseek(fp, 0x14000, SEEK_SET);
		fread(sa1_data, sa1_size, 1, fp);

		printf("SA1 signer is %s\n", sa1_cmd.signer);
		print_hash("SA1 content hash is", sa1_cmd.content_hash);
		print_key ("SA1 titlekey_iv is", sa1_cmd.titlekey_iv);
		print_key ("SA1 content_iv i ", sa1_cmd.content_iv);
		print_key("SA1 titlekey(crypted) is", sa1_cmd.titlekey);
		// first, decrypt the SA's titlekey with common key
		AES_init_ctx_iv(&ctx, key_common, sa1_cmd.titlekey_iv);
		AES_CBC_decrypt_buffer(&ctx, sa1_cmd.titlekey, 16);
		print_key("SA1 titlekey(decrypted) is", sa1_cmd.titlekey);
		// now use decrypted titlekey to decrypt the payload
		AES_init_ctx_iv(&ctx, sa1_cmd.titlekey, sa1_cmd.content_iv);
		AES_CBC_decrypt_buffer(&ctx, sa1_data, sa1_size);

		sha1_buffer(sa1_data, sa1_size, sa1_hash);
		print_hash("SA1 computed hash is", sa1_hash);
		if (memcmp(sa1_hash, sa1_cmd.content_hash, 20) == 0)
			printf("SA1 content hash matches internal hash\n") ;
		else 
			printf("SA1 content has does NOT match\n");

		// write decrypted to file
		fp_out = fopen(filename_sa1, "wb");
		fwrite(sa1_data, 1, sa1_size, fp_out);
		fclose(fp_out);
		if (memcmp(header_expected, sa1_data, 4) != 0) printf("Extracted SA1 contains some type of metadata, FYI.\n");
	}

	if (filename_sa2[0] != 0){
		if (filename_sa2[0] == 0) die("You must extract SA1 as well if you want SA2");
	
		printf("* Decrypting SA2 to file %s\n", filename_sa2);
		if (memcmp(key_empty, key_common, 16) == 0) die("Missing common key");
		fseek(fp, 0x14000 + sa1_size, SEEK_SET);
		fread(&sa2_cmd, sizeof(struct cmd), 1, fp);
		// please note while we've read in the data, all fields are wrong-endian so we must 
		// take care to endian swap any data we want to read from the struct
		sa2_size = BYTESWAP_32(sa2_cmd.content_size);
		if (sa2_size == 0) die("SA2 doesn't exist");
		printf("SA2 is %d/0x%X bytes\n", sa2_size, sa2_size);
		printf("SA2 is content ID %d\n", BYTESWAP_32(sa2_cmd.content_id));
		if (sa2_size % 16 != 0) die("SA2 size is not a modulus of 16, something is very wrong");
		sa2_data = malloc(sa2_size); if (sa2_size == NULL) die("Couldn't malloc SA2");
		fseek(fp, 0x18000 + sa1_size, SEEK_SET);
		fread(sa2_data, sa2_size, 1, fp);

		printf("SA2 signer is %s\n", sa2_cmd.signer);
		print_hash("SA2 content hash is", sa2_cmd.content_hash);
		print_key("SA2 titlekey_iv is", sa2_cmd.titlekey_iv);
		print_key("SA2 content_iv is", sa2_cmd.content_iv);
		print_key("SA2 titlekey(crypted) is", sa2_cmd.titlekey);
		// first, decrypt the SA's titlekey with common key
		AES_init_ctx_iv(&ctx, key_common, sa2_cmd.titlekey_iv);
		AES_CBC_decrypt_buffer(&ctx, sa2_cmd.titlekey, 16);
		print_key("SA2 titlekey(decrypted) is", sa2_cmd.titlekey);
		// now use decrypted titlekey to decrypt the payload
		AES_init_ctx_iv(&ctx, sa2_cmd.titlekey, sa2_cmd.content_iv);
		AES_CBC_decrypt_buffer(&ctx, sa2_data, sa2_size);

		sha1_buffer(sa2_data, sa2_size, sa2_hash);
		print_hash("SA2 computed hash is", sa2_hash);
		if (memcmp(sa1_hash, sa1_cmd.content_hash, 20) == 0)
			printf("SA2 content hash matches internal hash\n");
		else
			printf("SA2 content has does NOT match\n");

		// write decrypted to file
		fp_out = fopen(filename_sa2, "wb");
		fwrite(sa2_data, 1, sa2_size, fp_out);
		fclose(fp_out);
	}

	
	if (sk_data != NULL) free(sk_data);
	if (sa1_data != NULL) free(sa1_data);
	if (sa2_data != NULL) free(sa2_data);
	fclose(fp);

	printf("* Done\n");
	return 0;
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

void print_key(char *msg, unsigned char *key)
{
	if (!verbose) return;
	printf("%s ", msg);
	for (int k = 0; k <16; k++) { 
		printf("%02X", key[k]);
	} 
	printf("\n");
}

void print_hash(char *msg, unsigned char *hash)
{
	if (!verbose) return;
	printf("%s ", msg);
	for (int k = 0; k < 20; k++) {
		printf("%02X", hash[k]);
	}
	printf("\n");
}


