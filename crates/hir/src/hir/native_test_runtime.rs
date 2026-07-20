use std::collections::{BTreeMap, BTreeSet};

use crate::*;

#[derive(Debug)]
pub(crate) enum TestExecError {
    Failed(String),
    TimedOut(String),
    Unsupported(String),
}

#[derive(Default)]
pub(crate) struct NativeTestRuntime {
    next_handle: i32,
    tasks: BTreeMap<i32, Value>,
    lists: BTreeMap<i32, Vec<String>>,
    maps: BTreeMap<i32, BTreeMap<String, String>>,
    files: BTreeMap<String, String>,
    dirs: BTreeSet<String>,
    proc_argvs: BTreeMap<i32, Vec<String>>,
    proc_envs: BTreeMap<i32, BTreeMap<String, String>>,
    processes: BTreeMap<i32, TestProcess>,
    sql_counters: BTreeMap<String, i32>,
    sql_rows: BTreeMap<String, BTreeMap<String, String>>,
    clock: i32,
}

#[derive(Clone, Debug)]
struct TestProcess {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

impl NativeTestRuntime {
    pub(crate) fn new() -> Self {
        Self {
            next_handle: 1,
            tasks: BTreeMap::new(),
            lists: BTreeMap::new(),
            maps: BTreeMap::new(),
            files: BTreeMap::new(),
            dirs: BTreeSet::new(),
            proc_argvs: BTreeMap::new(),
            proc_envs: BTreeMap::new(),
            processes: BTreeMap::new(),
            sql_counters: BTreeMap::new(),
            sql_rows: BTreeMap::new(),
            clock: 0,
        }
    }

    pub(crate) fn alloc_task(&mut self, value: Value) -> i32 {
        let handle = self.alloc_handle();
        self.tasks.insert(handle, value);
        handle
    }

    pub(crate) fn task_result(&self, handle: i32) -> Result<Value, TestExecError> {
        self.tasks.get(&handle).cloned().ok_or_else(|| {
            TestExecError::Failed(format!("join requested unknown task handle `{handle}`"))
        })
    }

    pub(crate) fn invoke(
        &mut self,
        callee_name: &str,
        args: Vec<Value>,
    ) -> Result<Value, TestExecError> {
        match callee_name {
            "assert.eq_i32" => self.assert_eq_i32(args),
            "checkpoint" | "yield" | "pulse" | "recv" | "cancel" => {
                expect_arity(callee_name, &args, 0)?;
                Ok(Value::I32(0))
            }
            "timeout" | "deadline" | "time.sleep_ms" => {
                expect_arity(callee_name, &args, 1)?;
                let _ = require_i32(&args[0], callee_name)?;
                Ok(Value::I32(0))
            }
            "env.get" => {
                expect_arity(callee_name, &args, 1)?;
                let _ = require_str(&args[0], callee_name)?;
                Ok(Value::Str(String::new()))
            }
            "time.now" | "time.monotonic_ms" => {
                expect_arity(callee_name, &args, 0)?;
                self.clock += 1;
                Ok(Value::I32(self.clock))
            }
            "str.concat" | "str.concat2" => self.str_concat(callee_name, args),
            "str.concat3" => self.str_concat_n(callee_name, args, 3),
            "str.concat4" => self.str_concat_n(callee_name, args, 4),
            "str.from_i32" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::Str(require_i32(&args[0], callee_name)?.to_string()))
            }
            "str.from_bool" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::Str(
                    if truthy_value(&args[0]) {
                        "true"
                    } else {
                        "false"
                    }
                    .to_string(),
                ))
            }
            "str.contains" => self.str_predicate(callee_name, args, |haystack, needle| {
                haystack.contains(needle)
            }),
            "str.starts_with" => self.str_predicate(callee_name, args, |haystack, needle| {
                haystack.starts_with(needle)
            }),
            "str.ends_with" => self.str_predicate(callee_name, args, |haystack, needle| {
                haystack.ends_with(needle)
            }),
            "str.replace" => {
                expect_arity(callee_name, &args, 3)?;
                let value = require_str(&args[0], callee_name)?;
                let from = require_str(&args[1], callee_name)?;
                let to = require_str(&args[2], callee_name)?;
                Ok(Value::Str(value.replace(&from, &to)))
            }
            "str.trim" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::Str(
                    require_str(&args[0], callee_name)?.trim().to_string(),
                ))
            }
            "str.len" | "str.visible_len_ansi" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::I32(
                    require_str(&args[0], callee_name)?.chars().count() as i32,
                ))
            }
            "str.slice" => {
                expect_arity(callee_name, &args, 3)?;
                let value = require_str(&args[0], callee_name)?;
                let start = require_i32(&args[1], callee_name)?.max(0) as usize;
                let end = require_i32(&args[2], callee_name)?.max(0) as usize;
                let chars = value.chars().collect::<Vec<_>>();
                let start = start.min(chars.len());
                let end = end.min(chars.len()).max(start);
                Ok(Value::Str(chars[start..end].iter().collect()))
            }
            "str.upper_ascii" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::Str(
                    require_str(&args[0], callee_name)?.to_ascii_uppercase(),
                ))
            }
            "str.lower_ascii" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::Str(
                    require_str(&args[0], callee_name)?.to_ascii_lowercase(),
                ))
            }
            "str.repeat" => {
                expect_arity(callee_name, &args, 2)?;
                let value = require_str(&args[0], callee_name)?;
                let count = require_i32(&args[1], callee_name)?.max(0) as usize;
                Ok(Value::Str(value.repeat(count)))
            }
            "list.new" => {
                expect_arity(callee_name, &args, 0)?;
                let handle = self.alloc_handle();
                self.lists.insert(handle, Vec::new());
                Ok(Value::I32(handle))
            }
            "list.push" => {
                expect_arity(callee_name, &args, 2)?;
                let handle = require_handle(&args[0], callee_name)?;
                let value = require_str(&args[1], callee_name)?;
                self.lists
                    .get_mut(&handle)
                    .ok_or_else(|| unknown_handle(callee_name, handle))?
                    .push(value);
                Ok(Value::I32(0))
            }
            "list.len" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                Ok(Value::I32(
                    self.lists.get(&handle).map_or(0, |items| items.len()) as i32,
                ))
            }
            "list.get" => {
                expect_arity(callee_name, &args, 2)?;
                let handle = require_handle(&args[0], callee_name)?;
                let index = require_i32(&args[1], callee_name)?.max(0) as usize;
                Ok(Value::Str(
                    self.lists
                        .get(&handle)
                        .and_then(|items| items.get(index))
                        .cloned()
                        .unwrap_or_default(),
                ))
            }
            "list.join" => {
                expect_arity(callee_name, &args, 2)?;
                let handle = require_handle(&args[0], callee_name)?;
                let separator = require_str(&args[1], callee_name)?;
                Ok(Value::Str(
                    self.lists
                        .get(&handle)
                        .map(|items| items.join(&separator))
                        .unwrap_or_default(),
                ))
            }
            "map.new" => {
                expect_arity(callee_name, &args, 0)?;
                let handle = self.alloc_handle();
                self.maps.insert(handle, BTreeMap::new());
                Ok(Value::I32(handle))
            }
            "map.set" => {
                expect_arity(callee_name, &args, 3)?;
                let handle = require_handle(&args[0], callee_name)?;
                let key = require_str(&args[1], callee_name)?;
                let value = require_str(&args[2], callee_name)?;
                self.maps
                    .get_mut(&handle)
                    .ok_or_else(|| unknown_handle(callee_name, handle))?
                    .insert(key, value);
                Ok(Value::I32(0))
            }
            "map.get" => {
                expect_arity(callee_name, &args, 2)?;
                let handle = require_handle(&args[0], callee_name)?;
                let key = require_str(&args[1], callee_name)?;
                Ok(Value::Str(
                    self.maps
                        .get(&handle)
                        .and_then(|map| map.get(&key))
                        .cloned()
                        .unwrap_or_default(),
                ))
            }
            "map.has" => {
                expect_arity(callee_name, &args, 2)?;
                let handle = require_handle(&args[0], callee_name)?;
                let key = require_str(&args[1], callee_name)?;
                Ok(Value::I32(
                    if self
                        .maps
                        .get(&handle)
                        .is_some_and(|map| map.contains_key(&key))
                    {
                        1
                    } else {
                        0
                    },
                ))
            }
            "map.keys" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                let list = self.alloc_handle();
                let keys = self
                    .maps
                    .get(&handle)
                    .map(|map| map.keys().cloned().collect())
                    .unwrap_or_default();
                self.lists.insert(list, keys);
                Ok(Value::I32(list))
            }
            "map.len" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                Ok(Value::I32(
                    self.maps.get(&handle).map_or(0, BTreeMap::len) as i32
                ))
            }
            "json.escape" | "json.str" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::Str(json_quote(&require_str(&args[0], callee_name)?)))
            }
            "json.raw" | "json.parse" => {
                expect_arity(callee_name, &args, 1)?;
                Ok(Value::Str(require_str(&args[0], callee_name)?))
            }
            "json.object" | "json.from_map" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                let map = self
                    .maps
                    .get(&handle)
                    .ok_or_else(|| unknown_handle(callee_name, handle))?;
                let fields = map
                    .iter()
                    .map(|(key, value)| format!("{}:{}", json_quote(key), value))
                    .collect::<Vec<_>>()
                    .join(",");
                Ok(Value::Str(format!("{{{fields}}}")))
            }
            "json.array" | "json.from_list" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                let items = self
                    .lists
                    .get(&handle)
                    .ok_or_else(|| unknown_handle(callee_name, handle))?;
                Ok(Value::Str(format!("[{}]", items.join(","))))
            }
            "json.get_str" => {
                expect_arity(callee_name, &args, 2)?;
                let raw = require_str(&args[0], callee_name)?;
                let key = require_str(&args[1], callee_name)?;
                Ok(Value::Str(
                    json_field_raw(&raw, &key)
                        .map(|value| json_unquote(&value))
                        .unwrap_or_default(),
                ))
            }
            "json.has" => {
                expect_arity(callee_name, &args, 2)?;
                let raw = require_str(&args[0], callee_name)?;
                let key = require_str(&args[1], callee_name)?;
                Ok(Value::I32(if json_field_raw(&raw, &key).is_some() {
                    1
                } else {
                    0
                }))
            }
            "fs.mkdir" => {
                expect_arity(callee_name, &args, 1)?;
                self.dirs.insert(require_str(&args[0], callee_name)?);
                Ok(Value::I32(0))
            }
            "fs.write_file" | "fs.atomic_write" | "fs.write_bytes" => {
                expect_arity(callee_name, &args, 2)?;
                let path = require_str(&args[0], callee_name)?;
                let value = require_str(&args[1], callee_name)?;
                self.files.insert(path, value);
                Ok(Value::I32(0))
            }
            "fs.read_file" | "fs.read_bytes" => {
                expect_arity(callee_name, &args, 1)?;
                let path = require_str(&args[0], callee_name)?;
                Ok(Value::Str(
                    self.files.get(&path).cloned().unwrap_or_default(),
                ))
            }
            "fs.exists" | "fs.is_file" | "fs.is_dir" => {
                expect_arity(callee_name, &args, 1)?;
                let path = require_str(&args[0], callee_name)?;
                let exists = match callee_name {
                    "fs.is_file" => self.files.contains_key(&path),
                    "fs.is_dir" => self.dirs.contains(&path),
                    _ => self.files.contains_key(&path) || self.dirs.contains(&path),
                };
                Ok(Value::I32(if exists { 1 } else { 0 }))
            }
            "storage.atomic_append" | "storage.append" => {
                expect_arity(callee_name, &args, 2)?;
                let path = require_str(&args[0], callee_name)?;
                let value = require_str(&args[1], callee_name)?;
                self.files.entry(path).or_default().push_str(&value);
                Ok(Value::I32(0))
            }
            "proc.argv_new" => {
                expect_arity(callee_name, &args, 0)?;
                let handle = self.alloc_handle();
                self.proc_argvs.insert(handle, Vec::new());
                Ok(Value::I32(handle))
            }
            "proc.argv_push" => {
                expect_arity(callee_name, &args, 2)?;
                let handle = require_handle(&args[0], callee_name)?;
                let value = require_str(&args[1], callee_name)?;
                self.proc_argvs
                    .get_mut(&handle)
                    .ok_or_else(|| unknown_handle(callee_name, handle))?
                    .push(value);
                Ok(Value::I32(0))
            }
            "proc.env_new" => {
                expect_arity(callee_name, &args, 0)?;
                let handle = self.alloc_handle();
                self.proc_envs.insert(handle, BTreeMap::new());
                Ok(Value::I32(handle))
            }
            "proc.env_set" => {
                expect_arity(callee_name, &args, 3)?;
                let handle = require_handle(&args[0], callee_name)?;
                let key = require_str(&args[1], callee_name)?;
                let value = require_str(&args[2], callee_name)?;
                self.proc_envs
                    .get_mut(&handle)
                    .ok_or_else(|| unknown_handle(callee_name, handle))?
                    .insert(key, value);
                Ok(Value::I32(0))
            }
            "proc.spawn_cmd" => {
                expect_arity(callee_name, &args, 4)?;
                let executable = require_str(&args[0], callee_name)?;
                let argv = require_handle(&args[1], callee_name)?;
                let _env = require_handle(&args[2], callee_name)?;
                let _cwd = require_str(&args[3], callee_name)?;
                let process = self.spawn_cmd(&executable, argv)?;
                let handle = self.alloc_handle();
                self.processes.insert(handle, process);
                Ok(Value::I32(handle))
            }
            "proc.run" | "proc.run_cmd" => {
                expect_arity(callee_name, &args, 1)?;
                let command = require_str(&args[0], callee_name)?;
                Ok(Value::I32(self.run_command(&command)?))
            }
            "proc.wait" => {
                if args.len() != 1 && args.len() != 2 {
                    return Err(arity_error(callee_name, args.len(), "one or two"));
                }
                let handle = require_handle(&args[0], callee_name)?;
                if args.len() == 2 {
                    let _ = require_i32(&args[1], callee_name)?;
                }
                Ok(Value::I32(
                    self.processes
                        .get(&handle)
                        .map_or(0, |process| process.exit_code),
                ))
            }
            "proc.stdout" | "proc.read_stdout" => {
                self.process_field(callee_name, args, |p| &p.stdout)
            }
            "proc.stderr" | "proc.read_stderr" => {
                self.process_field(callee_name, args, |p| &p.stderr)
            }
            "proc.exit_code" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                Ok(Value::I32(
                    self.processes
                        .get(&handle)
                        .map_or(0, |process| process.exit_code),
                ))
            }
            "proc.close" | "close" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                self.processes.remove(&handle);
                Ok(Value::I32(0))
            }
            "term.write" | "term.write_err" | "term.print_line" | "log.info" | "log.warn"
            | "log.error" => {
                if args.len() != 1 {
                    return Err(arity_error(callee_name, args.len(), "one"));
                }
                let _ = require_str(&args[0], callee_name)?;
                Ok(Value::I32(0))
            }
            "log.fields" => {
                expect_arity(callee_name, &args, 1)?;
                let handle = require_handle(&args[0], callee_name)?;
                let map = self
                    .maps
                    .get(&handle)
                    .ok_or_else(|| unknown_handle(callee_name, handle))?;
                let fields = map
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                Ok(Value::Str(fields))
            }
            other => Err(TestExecError::Unsupported(format!(
                "runtime intrinsic `{other}` is not supported by the native test runner"
            ))),
        }
    }

    fn assert_eq_i32(&self, args: Vec<Value>) -> Result<Value, TestExecError> {
        expect_arity("assert.eq_i32", &args, 2)?;
        let lhs = require_i32(&args[0], "assert.eq_i32")?;
        let rhs = require_i32(&args[1], "assert.eq_i32")?;
        if lhs != rhs {
            return Err(TestExecError::Failed(format!(
                "assert.eq_i32 failed: left={lhs} right={rhs}"
            )));
        }
        Ok(Value::I32(0))
    }

    fn str_concat(&self, callee_name: &str, args: Vec<Value>) -> Result<Value, TestExecError> {
        expect_arity(callee_name, &args, 2)?;
        Ok(Value::Str(format!(
            "{}{}",
            require_str(&args[0], callee_name)?,
            require_str(&args[1], callee_name)?
        )))
    }

    fn str_concat_n(
        &self,
        callee_name: &str,
        args: Vec<Value>,
        expected: usize,
    ) -> Result<Value, TestExecError> {
        expect_arity(callee_name, &args, expected)?;
        let mut out = String::new();
        for arg in &args {
            out.push_str(&require_str(arg, callee_name)?);
        }
        Ok(Value::Str(out))
    }

    fn str_predicate(
        &self,
        callee_name: &str,
        args: Vec<Value>,
        predicate: impl FnOnce(&str, &str) -> bool,
    ) -> Result<Value, TestExecError> {
        expect_arity(callee_name, &args, 2)?;
        let haystack = require_str(&args[0], callee_name)?;
        let needle = require_str(&args[1], callee_name)?;
        Ok(Value::I32(if predicate(&haystack, &needle) {
            1
        } else {
            0
        }))
    }

    fn process_field(
        &self,
        callee_name: &str,
        args: Vec<Value>,
        field: impl FnOnce(&TestProcess) -> &String,
    ) -> Result<Value, TestExecError> {
        expect_arity(callee_name, &args, 1)?;
        let handle = require_handle(&args[0], callee_name)?;
        let process = self
            .processes
            .get(&handle)
            .ok_or_else(|| unknown_handle(callee_name, handle))?;
        Ok(Value::Str(field(process).clone()))
    }

    fn spawn_cmd(
        &mut self,
        executable: &str,
        argv_handle: i32,
    ) -> Result<TestProcess, TestExecError> {
        let argv = self
            .proc_argvs
            .get(&argv_handle)
            .cloned()
            .ok_or_else(|| unknown_handle("proc.spawn_cmd", argv_handle))?;
        if executable.ends_with("/sqlite3") || executable == "sqlite3" {
            let sql = argv.last().cloned().unwrap_or_default();
            let stdout = self.execute_sql(&sql);
            return Ok(TestProcess {
                stdout,
                stderr: String::new(),
                exit_code: 0,
            });
        }
        Err(TestExecError::Unsupported(format!(
            "deterministic native runner cannot spawn `{executable}`"
        )))
    }

    fn run_command(&mut self, command: &str) -> Result<i32, TestExecError> {
        if !command.contains("sqlite3") {
            return Err(TestExecError::Unsupported(format!(
                "deterministic native runner cannot execute shell command `{command}`"
            )));
        }
        let quoted = sqlite_command_quoted_values(command);
        let Some(sql) = quoted.iter().rev().find(|value| {
            value.contains("SELECT ")
                || value.contains("INSERT INTO ")
                || value.contains("UPDATE ")
                || value.contains("DELETE FROM ")
                || value.contains("PRAGMA ")
                || value.contains("CREATE TABLE ")
        }) else {
            return Err(TestExecError::Unsupported(format!(
                "sqlite shell command did not contain SQL: `{command}`"
            )));
        };
        let stdout = self.execute_sql(sql);
        if let Some((stdout_path, stderr_path)) = shell_redirect_paths(command) {
            self.files.insert(stdout_path, stdout);
            self.files.insert(stderr_path, String::new());
        }
        Ok(0)
    }

    fn execute_sql(&mut self, sql: &str) -> String {
        let mut selected = String::new();
        for statement in sql.split(';') {
            let statement = statement.trim();
            if statement.is_empty()
                || statement.starts_with("PRAGMA ")
                || statement.starts_with("CREATE TABLE ")
                || statement.starts_with("CREATE VIRTUAL TABLE ")
            {
                continue;
            }
            if statement.starts_with("INSERT INTO ") {
                self.sql_store_insert(statement);
            } else if statement.starts_with("UPDATE ") {
                self.sql_store_update(statement);
            } else if statement.starts_with("DELETE FROM ") {
                self.sql_store_delete(statement);
            } else if statement.starts_with("SELECT ") {
                selected = self.sql_select(statement);
            }
        }
        selected
    }

    fn sql_store_insert(&mut self, sql: &str) {
        let Some(table) = sql_table_after(sql, "INSERT INTO ") else {
            return;
        };
        let quoted = sql_quoted_values(sql);
        if table == "counters" {
            if let Some(name) = quoted.first() {
                self.sql_counters.entry(name.clone()).or_insert(0);
            }
            return;
        }
        let Some(id) = quoted.first().cloned() else {
            return;
        };
        let Some(payload) = quoted.last().cloned() else {
            return;
        };
        let key = sql_row_key(&table, &id);
        let row = self.sql_rows.entry(key).or_default();
        row.insert("id".to_string(), id.clone());
        row.insert("payload_json".to_string(), payload);
        if quoted.len() >= 3 {
            row.insert("owner".to_string(), quoted[1].clone());
        }
        if table == "sessions" {
            row.insert("session_id".to_string(), id.clone());
            if quoted.len() > 1 {
                row.insert("workspace_id".to_string(), quoted[1].clone());
            }
            if quoted.len() > 7 {
                row.insert("payload_json".to_string(), quoted[7].clone());
            }
            if quoted.len() > 8 {
                row.insert("registers_json".to_string(), quoted[8].clone());
            }
            if quoted.len() > 9 {
                row.insert("stack_json".to_string(), quoted[9].clone());
            }
            if quoted.len() > 10 {
                row.insert("frame_json".to_string(), quoted[10].clone());
            }
        }
        if table == "snapshots" {
            row.insert("snapshot_id".to_string(), id);
        }
        if table == "challenges" && quoted.len() >= 4 {
            row.insert("conviction_id".to_string(), quoted[1].clone());
            row.insert("investigation_id".to_string(), quoted[2].clone());
            row.insert("payload_json".to_string(), quoted[3].clone());
        }
        if table == "events" && quoted.len() >= 6 {
            row.insert("investigation_id".to_string(), quoted[1].clone());
            row.insert("entity_type".to_string(), quoted[2].clone());
            row.insert("entity_id".to_string(), quoted[3].clone());
            row.insert("event_kind".to_string(), quoted[4].clone());
            row.insert("payload_json".to_string(), quoted[5].clone());
        }
    }

    fn sql_store_delete(&mut self, sql: &str) {
        let Some(table) = sql_table_after(sql, "DELETE FROM ") else {
            return;
        };
        if table == "memory_search" {
            return;
        }
        if let Some(id) = sql_extract_where_id(sql) {
            self.sql_rows.remove(&sql_row_key(&table, &id));
            return;
        }
        let prefix = format!("{table}:");
        self.sql_rows.retain(|key, _| !key.starts_with(&prefix));
    }

    fn sql_store_update(&mut self, sql: &str) {
        let quoted = sql_quoted_values(sql);
        if sql.contains("UPDATE counters SET value = value + 1 WHERE name = ") {
            if let Some(name) = quoted.last() {
                *self.sql_counters.entry(name.clone()).or_insert(0) += 1;
            }
            return;
        }
        if sql.starts_with("UPDATE sessions SET ") && quoted.len() >= 2 {
            let session_id = quoted.last().cloned().unwrap_or_default();
            let value = quoted.first().cloned().unwrap_or_default();
            let key = sql_row_key("sessions", &session_id);
            let row = self.sql_rows.entry(key).or_default();
            row.insert("id".to_string(), session_id.clone());
            row.insert("session_id".to_string(), session_id);
            if sql.contains("registers_json") {
                row.insert("registers_json".to_string(), value);
            } else if sql.contains("stack_json") {
                row.insert("stack_json".to_string(), value);
            } else if sql.contains("frame_json") {
                row.insert("frame_json".to_string(), value);
            }
        }
    }

    fn sql_select(&self, sql: &str) -> String {
        let quoted = sql_quoted_values(sql);
        if sql.contains("SELECT CAST(value AS TEXT) FROM counters WHERE name = ") {
            return quoted
                .last()
                .and_then(|name| self.sql_counters.get(name))
                .copied()
                .unwrap_or(0)
                .to_string();
        }
        if sql.contains("SELECT CAST(COUNT(*) AS TEXT) FROM ") {
            let Some(table) = sql_table_after(sql, "FROM ") else {
                return "0".to_string();
            };
            if quoted.is_empty() {
                return self.count_rows(&table, None).to_string();
            }
            return self
                .count_rows(&table, quoted.last().map(String::as_str))
                .to_string();
        }
        if sql.contains("SELECT payload_json FROM ") {
            let Some(table) = sql_table_after(sql, "FROM ") else {
                return String::new();
            };
            let Some(id) = sql_extract_where_id(sql) else {
                return String::new();
            };
            return self
                .sql_rows
                .get(&sql_row_key(&table, &id))
                .and_then(|row| row.get("payload_json"))
                .cloned()
                .unwrap_or_default();
        }
        if sql.contains("SELECT id FROM ") {
            let Some(table) = sql_table_after(sql, "FROM ") else {
                return String::new();
            };
            let owner = quoted.last().map(String::as_str);
            return self.first_row_id(&table, owner);
        }
        for column in ["registers_json", "stack_json", "frame_json", "payload_json"] {
            let select = format!("SELECT {column} FROM sessions WHERE session_id = ");
            if sql.contains(&select) {
                let Some(id) = sql_extract_where_id(sql) else {
                    return String::new();
                };
                return self
                    .sql_rows
                    .get(&sql_row_key("sessions", &id))
                    .and_then(|row| row.get(column))
                    .cloned()
                    .unwrap_or_default();
            }
        }
        if sql.contains("group_concat") {
            let table = [
                "memories",
                "sessions",
                "links",
                "evidence",
                "assumptions",
                "hypotheses",
                "graph_nodes",
                "graph_edges",
                "convictions",
                "challenges",
                "events",
            ]
            .into_iter()
            .find(|candidate| sql.contains(&format!("FROM {candidate}")))
            .unwrap_or("");
            if !table.is_empty() {
                return self
                    .row_ids(table, quoted.last().map(String::as_str))
                    .join("\n");
            }
        }
        if sql.contains("json_group_array(json(payload_json))") {
            let table = [
                "memories",
                "evidence",
                "assumptions",
                "hypotheses",
                "graph_nodes",
                "graph_edges",
                "convictions",
                "challenges",
                "events",
            ]
            .into_iter()
            .find(|candidate| sql.contains(&format!("FROM {candidate}")))
            .unwrap_or("");
            if table.is_empty() {
                return "[]".to_string();
            }
            return format!(
                "[{}]",
                self.payloads(table, quoted.last().map(String::as_str))
                    .join(",")
            );
        }
        String::new()
    }

    fn count_rows(&self, table: &str, owner: Option<&str>) -> usize {
        self.sql_rows
            .iter()
            .filter(|(key, row)| {
                key.starts_with(&format!("{table}:"))
                    && owner.is_none_or(|owner| row.values().any(|value| value == owner))
            })
            .count()
    }

    fn row_ids(&self, table: &str, owner: Option<&str>) -> Vec<String> {
        let prefix = format!("{table}:");
        self.sql_rows
            .iter()
            .filter(|(key, row)| {
                key.starts_with(&prefix)
                    && owner.is_none_or(|owner| row.values().any(|value| value == owner))
            })
            .filter_map(|(key, _)| key.strip_prefix(&prefix).map(str::to_string))
            .collect()
    }

    fn first_row_id(&self, table: &str, owner: Option<&str>) -> String {
        self.row_ids(table, owner)
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    fn payloads(&self, table: &str, owner: Option<&str>) -> Vec<String> {
        let prefix = format!("{table}:");
        self.sql_rows
            .iter()
            .filter(|(key, row)| {
                key.starts_with(&prefix)
                    && owner.is_none_or(|owner| row.values().any(|value| value == owner))
            })
            .filter_map(|(_, row)| row.get("payload_json").cloned())
            .collect()
    }

    fn alloc_handle(&mut self) -> i32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }
}

fn expect_arity(name: &str, args: &[Value], expected: usize) -> Result<(), TestExecError> {
    if args.len() == expected {
        return Ok(());
    }
    Err(arity_error(name, args.len(), &expected.to_string()))
}

fn arity_error(name: &str, actual: usize, expected: &str) -> TestExecError {
    TestExecError::Unsupported(format!(
        "`{name}` expects {expected} argument(s), got {actual}"
    ))
}

fn unknown_handle(name: &str, handle: i32) -> TestExecError {
    TestExecError::Failed(format!(
        "`{name}` received unknown runtime handle `{handle}`"
    ))
}

fn require_i32(value: &Value, context: &str) -> Result<i32, TestExecError> {
    match value {
        Value::I32(v) => Ok(*v),
        Value::Bool(v) => Ok(if *v { 1 } else { 0 }),
        Value::Char(v) => Ok(*v as i32),
        Value::F64(v) => Ok(*v as i32),
        _ => Err(TestExecError::Unsupported(format!(
            "{context} requires an integer-compatible value"
        ))),
    }
}

fn require_handle(value: &Value, context: &str) -> Result<i32, TestExecError> {
    require_i32(value, context)
}

fn require_str(value: &Value, context: &str) -> Result<String, TestExecError> {
    match value {
        Value::Str(v) => Ok(v.clone()),
        Value::I32(v) => Ok(v.to_string()),
        Value::Bool(v) => Ok(if *v { "true" } else { "false" }.to_string()),
        Value::Char(v) => Ok(v.to_string()),
        Value::F64(v) => Ok(v.to_string()),
        _ => Err(TestExecError::Unsupported(format!(
            "{context} requires a string-compatible value"
        ))),
    }
}

fn truthy_value(value: &Value) -> bool {
    match value {
        Value::Bool(v) => *v,
        Value::I32(v) => *v != 0,
        Value::F64(v) => *v != 0.0,
        Value::Char(v) => *v != '\0',
        Value::Str(v) => !v.is_empty(),
        Value::Tuple(v) | Value::List(v) => !v.is_empty(),
        Value::FnRef(_) | Value::Closure(_) | Value::Struct { .. } | Value::Enum { .. } => true,
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn json_quote(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn json_unquote(value: &str) -> String {
    let trimmed = value.trim();
    if !(trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2) {
        return trimmed.to_string();
    }
    let mut out = String::new();
    let mut chars = trimmed[1..trimmed.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => break,
        }
    }
    out
}

fn json_field_raw(input: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", json_escape(key));
    let start = input.find(&needle)? + needle.len();
    let rest = input[start..].trim_start();
    if rest.starts_with('"') {
        let mut escaped = false;
        for (idx, ch) in rest.char_indices().skip(1) {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '"' {
                return Some(rest[..=idx].to_string());
            }
        }
        return None;
    }
    let mut depth = 0i32;
    for (idx, ch) in rest.char_indices() {
        match ch {
            '{' | '[' => depth += 1,
            '}' | ']' if depth > 0 => depth -= 1,
            ',' | '}' if depth == 0 => return Some(rest[..idx].trim().to_string()),
            _ => {}
        }
    }
    Some(rest.trim().to_string())
}

fn sql_quoted_values(sql: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            continue;
        }
        let mut value = String::new();
        while let Some(next) = chars.next() {
            if next == '\'' {
                if matches!(chars.peek(), Some('\'')) {
                    let _ = chars.next();
                    value.push('\'');
                    continue;
                }
                break;
            }
            value.push(next);
        }
        values.push(value);
    }
    values
}

fn sql_table_after(sql: &str, marker: &str) -> Option<String> {
    let start = sql.find(marker)? + marker.len();
    let rest = sql[start..].trim_start();
    let table = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    if table.is_empty() {
        None
    } else {
        Some(table)
    }
}

fn sql_row_key(table: &str, id: &str) -> String {
    format!("{table}:{id}")
}

fn sql_extract_where_id(sql: &str) -> Option<String> {
    sql_quoted_values(sql).last().cloned()
}

fn shell_quoted_values(command: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            continue;
        }
        let mut value = String::new();
        while let Some(next) = chars.next() {
            if next == '\'' {
                if matches!(chars.peek(), Some('\\')) {
                    let _ = chars.next();
                    if matches!(chars.peek(), Some('\'')) {
                        let _ = chars.next();
                        value.push('\'');
                        if matches!(chars.peek(), Some('\'')) {
                            let _ = chars.next();
                        }
                        continue;
                    }
                    value.push('\\');
                    continue;
                }
                break;
            }
            value.push(next);
        }
        values.push(value);
    }
    values
}

fn sqlite_command_quoted_values(command: &str) -> Vec<String> {
    let quoted = shell_quoted_values(command);
    if quoted.len() == 1 && quoted[0].contains("sqlite3") {
        return shell_quoted_values(&quoted[0]);
    }
    quoted
}

fn shell_redirect_paths(command: &str) -> Option<(String, String)> {
    let quoted = sqlite_command_quoted_values(command);
    if quoted.len() < 2 {
        return None;
    }
    let stdout_path = quoted.get(quoted.len().saturating_sub(2))?.clone();
    let stderr_path = quoted.last()?.clone();
    Some((stdout_path, stderr_path))
}
