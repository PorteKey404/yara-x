// aot compile <rules.yar> <rules.aot>
// aot scan <rules.aot> <file>...
#define YRX_AOT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara_x.h>

static int fail(const char *what) {
  fprintf(stderr, "%s: %s\n", what, yrx_last_error());
  return 1;
}

static void on_match(const struct YRX_RULE *rule, void *file) {
  const uint8_t *id;
  size_t len;
  yrx_rule_identifier(rule, &id, &len);
  printf("%.*s %s\n", (int)len, (const char *)id, (const char *)file);
}

static int compile(const char *src_path, const char *aot_path) {
  FILE *f = fopen(src_path, "rb");
  if (!f)
    return perror(src_path), 1;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  rewind(f);
  char *src = malloc(n + 1);
  if (fread(src, 1, n, f) != (size_t)n)
    return perror(src_path), 1;
  src[n] = 0;
  fclose(f);

  struct YRX_RULES *rules;
  struct YRX_BUFFER *buf;
  if (yrx_compile(src, &rules) != YRX_SUCCESS)
    return fail(src_path);
  if (yrx_rules_serialize_aot(rules, &buf) != YRX_SUCCESS)
    return fail(aot_path);

  // Jamais réécrit en place : un fichier chargé ailleurs ferait SIGBUS
  char tmp[4096];
  snprintf(tmp, sizeof tmp, "%s.tmp", aot_path);
  f = fopen(tmp, "wb");
  if (!f || fwrite(buf->data, 1, buf->length, f) != buf->length ||
      fclose(f) != 0 || rename(tmp, aot_path) != 0)
    return perror(aot_path), 1;

  yrx_buffer_destroy(buf);
  yrx_rules_destroy(rules);
  free(src);
  return 0;
}

static int scan(const char *aot_path, char **files, int nfiles) {
  struct YRX_RULES *rules;
  struct YRX_SCANNER *scanner;
  if (yrx_rules_deserialize_aot_file(aot_path, &rules) != YRX_SUCCESS)
    return fail(aot_path);
  if (yrx_scanner_create(rules, &scanner) != YRX_SUCCESS)
    return fail(aot_path);
  for (int i = 0; i < nfiles; i++) {
    yrx_scanner_on_matching_rule(scanner, on_match, files[i]);
    if (yrx_scanner_scan_file(scanner, files[i]) != YRX_SUCCESS)
      return fail(files[i]);
  }
  yrx_scanner_destroy(scanner);
  yrx_rules_destroy(rules);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && !strcmp(argv[1], "compile"))
    return compile(argv[2], argv[3]);
  if (argc >= 4 && !strcmp(argv[1], "scan"))
    return scan(argv[2], argv + 3, argc - 3);
  fprintf(stderr, "usage: aot compile <rules.yar> <rules.aot>\n"
                  "       aot scan <rules.aot> <file>...\n");
  return 2;
}
