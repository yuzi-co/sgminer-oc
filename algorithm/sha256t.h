#ifndef SHA256T_H
#define SHA256T_H

#include "miner.h"

extern int sha256t_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce);
extern void sha256t_prepare_work(dev_blk_ctx *blk, uint32_t *state, uint32_t *pdata);
extern void sha256t_midstate(struct work *work);
extern void sha256t_regenhash(struct work *work);

#endif /* SHA256T_H */