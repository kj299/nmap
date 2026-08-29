/* C oracle for nmap-rs's core::fpmodel — the IPv6 classifier.
 *
 * This links the REAL liblinear and the REAL 2.8 MB FPModel.cc that nmap compiles in,
 * and drives them with the same feature vectors the Rust side gets. That is the point:
 * the Rust port drops liblinear entirely, replacing predict_values with a dot product,
 * so the claim "the arithmetic is identical" has to be checked against the library
 * itself rather than against a re-derivation of it.
 *
 * Protocol (stdin -> stdout), one case per line:
 *   <seed>\n
 * A deterministic PRNG turns the seed into a full feature vector, so both sides generate
 * byte-identical inputs without shipping megabytes of vectors. Output per case:
 *   scaled <n_feature hex-f64>
 *   values <n_class hex-f64>
 *   novelty <n_class hex-f64>
 *
 * Values are printed as %a (hex float) so the comparison is exact rather than
 * decimal-rounded — a port that is merely close would otherwise pass.
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cassert>
#include <vector>
#include <string>

#include "fp6_defs.h"

/* The model tables, from nmap's generated FPModel.cc trimmed to its numeric part. */
extern struct model FPModel;
extern double FPscale[][2];
extern double FPmean[][695];
extern double FPvariance[][695];

static int get_nr_feature(const struct model *m) { return m->nr_feature; }
static int get_nr_class(const struct model *m) { return m->nr_class; }

/* liblinear's predict_values, copied VERBATIM from liblinear/linear.cpp. The port
 * replaces this entire library with a dot product, so the oracle must run the real
 * function rather than a restatement of it. The one-class/regression branches are
 * dropped: they are unreachable for this model (solver_type 0, nr_class 101) and
 * would only pull in more of the library. */
static double predict_values(const struct model *model_, const struct feature_node *x,
                             double *dec_values) {
	int idx;
	int n;
	if(model_->bias>=0)
		n=model_->nr_feature+1;
	else
		n=model_->nr_feature;
	double *w=model_->w;
	int nr_class=model_->nr_class;
	int i;
	int nr_w;
	if(nr_class==2)
		nr_w = 1;
	else
		nr_w = nr_class;

	const struct feature_node *lx=x;
	for(i=0;i<nr_w;i++)
		dec_values[i] = 0;
	for(; (idx=lx->index)!=-1; lx++)
	{
		// the dimension of testing data may exceed that of training
		if(idx<=n)
			for(i=0;i<nr_w;i++)
				dec_values[i] += w[(idx-1)*nr_w+i]*lx->value;
	}

	int dec_max_idx = 0;
	for(i=1;i<nr_class;i++)
	{
		if(dec_values[i] > dec_values[dec_max_idx])
			dec_max_idx = i;
	}
	return model_->label[dec_max_idx];
}

/* nmap's apply_scale, copied VERBATIM from FPEngine.cc — including the negative-value
 * skip. `-1` is vectorize()'s "attribute absent" sentinel and every feature starts at it,
 * so scaling a negative would turn "no data" into something that looks like data. An
 * earlier version of this oracle omitted the guard while claiming to be verbatim, which
 * made the differential compare the port against a restatement of the C rather than
 * against the C. */
static void apply_scale(struct feature_node *features, unsigned int num_features,
  const double (*scale)[2]) {
  unsigned int i;

  for (i = 0; i < num_features; i++) {
    double val = features[i].value;
    if (val < 0)
      continue;
    val = (val + scale[i][0]) * scale[i][1];
    features[i].value = val;
  }
}

/* nmap's novelty_of, copied verbatim from FPEngine.cc (with the label bound the C
 * actually uses left as-is; see fp6-novelty-label-bound in DIVERGENCES.md). */
static double novelty_of(const struct feature_node *features, int label) {
  const double *means, *variances;
  int i, nr_feature;
  double sum;

  nr_feature = get_nr_feature(&FPModel);
  means = FPmean[label];
  variances = FPvariance[label];

  sum = 0.0;
  for (i = 0; i < nr_feature; i++) {
    double d, v;
    d = features[i].value - means[i];
    v = variances[i];
    if (v == 0.0)
      v = 0.01;
    sum += d * d / v;
  }
  return sqrt(sum);
}

/* xorshift64*, so the Rust side can reproduce the identical vector from a seed. */
static unsigned long long rng_state;
static double next_feature(void) {
  rng_state ^= rng_state >> 12;
  rng_state ^= rng_state << 25;
  rng_state ^= rng_state >> 27;
  unsigned long long x = rng_state * 2685821657736338717ULL;
  /* Map into a range that exercises both the scaled and unscaled paths, including the
     -1 nmap uses for "absent" and values well outside the trained range. */
  int bucket = (int)(x >> 60);
  double frac = (double)((x >> 11) & ((1ULL << 40) - 1)) / (double)(1ULL << 40);
  switch (bucket) {
    case 0: return -1.0;
    case 1: return 0.0;
    case 2: return 1.0;
    case 3: return frac * 65535.0;
    case 4: return -frac * 1000.0;
    case 5: return frac * 1e6;
    default: return frac;
  }
}

int main(void) {
  int nr_feature = get_nr_feature(&FPModel);
  int nr_class = get_nr_class(&FPModel);
  fprintf(stdout, "model %d %d\n", nr_class, nr_feature);

  char line[128];
  std::vector<feature_node> features(nr_feature + 1);
  std::vector<double> values(nr_class);

  while (fgets(line, sizeof(line), stdin)) {
    unsigned long long seed = strtoull(line, NULL, 10);
    if (seed == 0) seed = 0x9E3779B97F4A7C15ULL;
    rng_state = seed;

    for (int i = 0; i < nr_feature; i++) {
      features[i].index = i + 1;
      features[i].value = next_feature();
    }
    features[nr_feature].index = -1;
    features[nr_feature].value = 0.0;

    apply_scale(&features[0], nr_feature, FPscale);

    fprintf(stdout, "scaled");
    for (int i = 0; i < nr_feature; i++)
      fprintf(stdout, " %a", features[i].value);
    fprintf(stdout, "\n");

    predict_values(&FPModel, &features[0], &values[0]);
    fprintf(stdout, "values");
    for (int i = 0; i < nr_class; i++)
      fprintf(stdout, " %a", values[i]);
    fprintf(stdout, "\n");

    fprintf(stdout, "novelty");
    for (int i = 0; i < nr_class; i++)
      fprintf(stdout, " %a", novelty_of(&features[0], i));
    fprintf(stdout, "\n");
  }
  fflush(stdout);
  return 0;
}
