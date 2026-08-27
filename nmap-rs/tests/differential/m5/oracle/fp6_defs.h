/* liblinear's data structures, transcribed from liblinear/linear.h.
 *
 * Shared by fp6_oracle.cc and the trimmed copy of nmap's generated FPModel.cc that
 * build_fp6_oracle.sh produces. Only the fields predict_values reads are needed;
 * `parameter` is opaque here because this model's solver_type is 0 (L2R_LR), never
 * MCSVM_CS, so the branches keyed on it are unreachable. */
#ifndef FP6_DEFS_H
#define FP6_DEFS_H

struct parameter { int solver_type; };
struct feature_node { int index; double value; };
struct model {
  struct parameter param;
  int nr_class;
  int nr_feature;
  double *w;
  int *label;
  double bias;
  double rho;
};

#endif
