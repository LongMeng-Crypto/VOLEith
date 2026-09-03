/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "vole.h"
#include "aes.h"
#include "utils.h"
#include "random_oracle.h"

#include <stdbool.h>
#include <string.h>

static const uint32_t TWEAK_OFFSET = UINT32_C(0x80000000); // 2^31

static unsigned int convert_to_vole_with_scratch(
    const uint8_t* iv, const uint8_t* sd, bool sd0_bot, unsigned int i,
    unsigned int outlen, uint8_t* u, uint8_t* v,
    const faest_paramset_t* params, uint8_t* scratch) {
  const unsigned int lambda        = params->lambda;
  const unsigned int tau_1         = params->tau1;
  const unsigned int k             = params->k;
  const unsigned int num_instances = bavc_max_node_index(i, tau_1, k);
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int depth         = bavc_max_node_depth(i, tau_1, k);

#define V(idx) (v + (idx) * outlen)

  /* Fold the binary tree online. The caller reuses this scratch allocation
   * across every tree in one VOLE operation. A public bit mask records which
   * stack levels are occupied, so no clearing or per-tree allocation is
   * needed. */
  assert(depth < 64);
  uint8_t* stack = scratch;
  uint8_t* current = scratch + (MAX_DEPTH + 1) * outlen;
  uint64_t occupied = 0;

  uint32_t tweak = i ^ TWEAK_OFFSET;

  memset(v, 0, depth * outlen);

  for (unsigned int leaf = 0; leaf < num_instances; ++leaf) {
    if (sd0_bot && leaf == 0) {
      memset(current, 0, outlen);
    } else {
      prg(sd + lambda_bytes * leaf, iv, tweak, current, lambda, outlen);
    }

    unsigned int level = 0;
    while ((occupied >> level) & 1) {
      xor_u8_array(V(level), current, V(level), outlen);
      xor_u8_array(stack + level * outlen, current, current, outlen);
      occupied &= ~(UINT64_C(1) << level);
      ++level;
    }
    memcpy(stack + level * outlen, current, outlen);
    occupied |= UINT64_C(1) << level;
  }

  // Step: 10
  if (!sd0_bot && u != NULL) {
    memcpy(u, stack + depth * outlen, outlen);
  }
  return depth;
}

#if defined(FAEST_TESTS)
unsigned int convert_to_vole(const uint8_t* iv, const uint8_t* sd,
                             bool sd0_bot, unsigned int i,
                             unsigned int outlen, uint8_t* u, uint8_t* v,
                             const faest_paramset_t* params) {
  uint8_t* scratch = malloc((MAX_DEPTH + 2) * outlen);
  assert(scratch);
  const unsigned int depth = convert_to_vole_with_scratch(
      iv, sd, sd0_bot, i, outlen, u, v, params, scratch);
  free(scratch);
  return depth;
}
#endif

void vole_commit(const uint8_t* rootKey, const uint8_t* iv, unsigned int ellhat,
                 const faest_paramset_t* params, bavc_t* bavc, uint8_t* c, uint8_t* u,
                 uint8_t** v) {
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int k            = params->k;

  bavc_commit(bavc, rootKey, iv, params);

  uint8_t* ui = malloc(tau * ellhat_bytes);
  uint8_t* convert_scratch = malloc((MAX_DEPTH + 2) * ellhat_bytes);
  assert(ui);
  assert(convert_scratch);

  unsigned int v_idx = 0;
  uint8_t* sd_i      = bavc->sd;
  for (unsigned int i = 0; i < tau; ++i) {
    // Step 6
    v_idx += convert_to_vole_with_scratch(
        iv, sd_i, false, i, ellhat_bytes, ui + i * ellhat_bytes, v[v_idx],
        params, convert_scratch);
    sd_i += lambda_bytes * bavc_max_node_index(i, tau_1, k);
  }

  // ensure 0-padding up to lambda
  for (; v_idx != lambda; ++v_idx) {
    memset(v[v_idx], 0, ellhat_bytes);
  }

  // Step 9
  memcpy(u, ui, ellhat_bytes);
  for (unsigned int i = 1; i < tau; i++) {
    // Step 11
    xor_u8_array(u, ui + i * ellhat_bytes, c + (i - 1) * ellhat_bytes, ellhat_bytes);
  }
  free(ui);
  free(convert_scratch);
}

bool vole_reconstruct(uint8_t* com, uint8_t** q, const uint8_t* iv, const uint8_t* chall_3,
                      const uint8_t* decom_i, const uint8_t* c, unsigned int ellhat,
                      const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau1         = params->tau1;
  const unsigned int L            = params->L;
  const unsigned int k            = params->k;

  uint16_t i_delta[MAX_TAU];
  if (!decode_all_chall_3(i_delta, chall_3, params)) {
    return false;
  }

  bavc_rec_t bavc_rec;
  bavc_rec.h = com;
  bavc_rec.s = malloc((L - tau) * lambda_bytes);
  assert(bavc_rec.s);

  if (!bavc_reconstruct(&bavc_rec, decom_i, i_delta, iv, params)) {
    free(bavc_rec.s);
    return false;
  }

  uint8_t* sd   = malloc((1 << k) * lambda_bytes);
  uint8_t* qtmp = malloc(MAX_DEPTH * ellhat_bytes);
  uint8_t* convert_scratch = malloc((MAX_DEPTH + 2) * ellhat_bytes);
  assert(sd);
  assert(qtmp);
  assert(convert_scratch);

  // Step: 1
  unsigned int q_idx = 0;
  uint8_t* sd_i      = bavc_rec.s;
  for (unsigned int i = 0; i < tau; i++) {
    // Step: 2
    const unsigned int Ni = bavc_max_node_index(i, tau1, k);

    // Step: 6
    for (unsigned int j = 0; j < Ni; j++) {
      if (j < i_delta[i]) {
        memcpy(sd + (j ^ i_delta[i]) * lambda_bytes, sd_i + lambda_bytes * j, lambda_bytes);
      } else if (j > i_delta[i]) {
        memcpy(sd + (j ^ i_delta[i]) * lambda_bytes, sd_i + lambda_bytes * (j - 1), lambda_bytes);
      }
    }

    // Step: 7..8
    const unsigned int ki = convert_to_vole_with_scratch(
        iv, sd, true, i, ellhat_bytes, NULL, qtmp, params, convert_scratch);

    // Step 11
    if (i == 0) {
      // Step 8
      memcpy(q[q_idx], qtmp, ellhat_bytes * ki);
      q_idx += ki;
    } else {
      // Step 14
      for (unsigned int d = 0; d < ki; ++d, ++q_idx) {
        masked_xor_u8_array(qtmp + d * ellhat_bytes, c + (i - 1) * ellhat_bytes, q[q_idx],
                            (i_delta[i] >> d) & 1, ellhat_bytes);
      }
    }
    sd_i += lambda_bytes * (Ni - 1);
  }

  // ensure 0-padding up to lambda
  for (; q_idx != lambda; ++q_idx) {
    memset(q[q_idx], 0, ellhat_bytes);
  }

  free(qtmp);
  free(convert_scratch);
  free(sd);
  free(bavc_rec.s);
  return true;
}
