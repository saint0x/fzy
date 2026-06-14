pub(super) fn section() -> &'static str {
    r#"

static int fz_env_key_match(const char* entry, const char* key, size_t key_len) {
  if (entry == NULL || key == NULL) {
    return 0;
  }
  return strncmp(entry, key, key_len) == 0 && entry[key_len] == '=';
}

static char** fz_clone_env_with_overrides(char** overrides, int override_count) {
  int base_count = 0;
  while (environ != NULL && environ[base_count] != NULL) {
    base_count++;
  }
  int cap = base_count + override_count + 1;
  char** envp = (char**)calloc((size_t)cap, sizeof(char*));
  if (envp == NULL) {
    return NULL;
  }
  int count = 0;
  for (int i = 0; i < base_count; i++) {
    envp[count] = strdup(environ[i]);
    if (envp[count] == NULL) {
      for (int j = 0; j < count; j++) free(envp[j]);
      free(envp);
      return NULL;
    }
    count++;
  }
  for (int i = 0; i < override_count; i++) {
    const char* item = overrides[i];
    const char* eq = item == NULL ? NULL : strchr(item, '=');
    if (eq == NULL || eq == item) {
      continue;
    }
    size_t key_len = (size_t)(eq - item);
    int replaced = 0;
    for (int j = 0; j < count; j++) {
      if (fz_env_key_match(envp[j], item, key_len)) {
        char* dup = strdup(item);
        if (dup == NULL) {
          continue;
        }
        free(envp[j]);
        envp[j] = dup;
        replaced = 1;
        break;
      }
    }
    if (!replaced && count < cap - 1) {
      envp[count] = strdup(item);
      if (envp[count] != NULL) {
        count++;
      }
    }
  }
  envp[count] = NULL;
  return envp;
}

static void fz_free_env(char** envp) {
  if (envp == NULL) {
    return;
  }
  for (int i = 0; envp[i] != NULL; i++) {
    free(envp[i]);
  }
  free(envp);
}

"#
}
