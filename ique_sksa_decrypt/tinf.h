/*
 * tinf  -  tiny inflate library (inflate, gzip, zlib)
 *
 * version 1.00
 *
 * Copyright (c) 2003 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef TINF_H_INCLUDED
#define TINF_H_INCLUDED

/* calling convention */
#ifndef TINFCC
 #ifdef __WATCOMC__
  #define TINFCC __cdecl
 #else
  #define TINFCC
 #endif
#endif

#define TINF_OK             0
#define TINF_DATA_ERROR    (-3)

/* function prototypes */

void TINFCC tinf_init();

int TINFCC tinf_uncompress(void *dest, unsigned int *destLen,
                           const void *source, unsigned int sourceLen);

#endif /* TINF_H_INCLUDED */
