# ique_sksa_decrypt

ique_sksa_decrypt 0.1 by marshallh \
---------------------------------- \
Arguments: ique_sksa_decrypt \
         -f <sksa_in_file_name>\
        [-skout <sk_out filename>] \
        [-sa1out <sa1_out filename>] \
        [-sa2out <sa2_out filename>] \
         -ckey <common_key> \
         -skey <sk_key> \
         -siv <sk_iv> \
         -v (enables verbose printing of values) 
         

You may either choose to extract SK, SA1, or SA1+SA2.\
Specifying a filename means you want to extract it.\
\
Tested on all SKSA known from content ID 1009 to 1106. \
SA2 doesn't seem to be final plaintext yet, but hash verifies.???
