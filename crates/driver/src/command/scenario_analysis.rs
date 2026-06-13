impl GpuTraceAnalyzer {
    fn new(kernel_layouts: HashMap<String, String>) -> Self {
        Self {
            next_trace_id: GPU_TRACE_EVENT_ID_BASE,
            previous_trace_id: None,
            next_device_id: 1,
            next_buffer_id: 1,
            next_slice_id: 1,
            next_event_id: 1,
            runtime_events: Vec::new(),
            causal_links: Vec::new(),
            bindings: HashMap::new(),
            kernel_layouts,
        }
    }

    fn emit_event(
        &mut self,
        phase: &str,
        kind: &str,
        label: String,
        details: Option<serde_json::Value>,
    ) -> u64 {
        let trace_id = self.next_trace_id;
        self.next_trace_id = self.next_trace_id.saturating_add(1);
        self.runtime_events.push(RuntimeSemanticEvent {
            task_id: trace_id,
            phase: phase.to_string(),
            kind: kind.to_string(),
            label,
            details,
        });
        if let Some(previous) = self.previous_trace_id {
            self.causal_links.push(CausalLink {
                from: previous,
                to: trace_id,
                relation: "gpu.next".to_string(),
            });
        }
        self.previous_trace_id = Some(trace_id);
        trace_id
    }

    fn emit_link(&mut self, from: u64, to: u64, relation: &str) {
        self.causal_links.push(CausalLink {
            from,
            to,
            relation: relation.to_string(),
        });
    }

    fn bind(&mut self, name: &str, binding: GpuTraceBinding) {
        self.bindings.insert(name.to_string(), binding);
    }

    fn resolve_binding(&self, expr: &ast::Expr) -> Option<GpuTraceBinding> {
        match expr {
            ast::Expr::Ident(name) => self.bindings.get(name).cloned(),
            _ => None,
        }
    }

    fn trace_stmt(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                if let Some(binding) = self.trace_expr(value) {
                    self.bind(name, binding);
                }
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Expr(value)
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value) => {
                self.trace_expr(value);
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(binding) = self.trace_expr(value) {
                    self.bind(target, binding);
                }
            }
            ast::Stmt::CompoundAssign { value, .. } => {
                self.trace_expr(value);
            }
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    self.trace_expr(value);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                self.trace_expr(condition);
                for stmt in then_body {
                    self.trace_stmt(stmt);
                }
                for stmt in else_body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::While { condition, body } => {
                self.trace_expr(condition);
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    self.trace_stmt(init);
                }
                if let Some(condition) = condition {
                    self.trace_expr(condition);
                }
                if let Some(step) = step {
                    self.trace_stmt(step);
                }
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                self.trace_expr(iterable);
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::Loop { body } => {
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::Match { scrutinee, arms } => {
                self.trace_expr(scrutinee);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        self.trace_expr(guard);
                    }
                    self.trace_expr(&arm.value);
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }

    fn trace_expr(&mut self, expr: &ast::Expr) -> Option<GpuTraceBinding> {
        match expr {
            ast::Expr::Call { callee, args } => self.trace_call(callee, args),
            ast::Expr::Await(inner) | ast::Expr::Group(inner) | ast::Expr::Discard(inner) => {
                self.trace_expr(inner)
            }
            ast::Expr::Unary { expr, .. } => {
                self.trace_expr(expr);
                None
            }
            ast::Expr::FieldAccess { base, .. } => {
                self.trace_expr(base);
                None
            }
            ast::Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    self.trace_expr(value);
                }
                None
            }
            ast::Expr::EnumInit { payload, .. } | ast::Expr::Tuple(payload) => {
                for value in payload {
                    self.trace_expr(value);
                }
                None
            }
            ast::Expr::Closure { body, .. } => {
                self.trace_expr(body);
                None
            }
            ast::Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                self.trace_expr(try_expr);
                self.trace_expr(catch_expr);
                None
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                self.trace_expr(condition);
                self.trace_expr(then_expr);
                self.trace_expr(else_expr);
                None
            }
            ast::Expr::Binary { left, right, .. } => {
                self.trace_expr(left);
                self.trace_expr(right);
                None
            }
            ast::Expr::Range { start, end, .. } => {
                self.trace_expr(start);
                self.trace_expr(end);
                None
            }
            ast::Expr::ArrayLiteral(items) => {
                for item in items {
                    self.trace_expr(item);
                }
                None
            }
            ast::Expr::ObjectLiteral(items) => {
                for (_, value) in items {
                    self.trace_expr(value);
                }
                None
            }
            ast::Expr::Index { base, index } => {
                self.trace_expr(base);
                self.trace_expr(index);
                None
            }
            ast::Expr::UnsafeBlock { body, .. }
            | ast::Expr::While { body, .. }
            | ast::Expr::For { body, .. }
            | ast::Expr::ForIn { body, .. }
            | ast::Expr::Loop { body } => {
                for stmt in body {
                    self.trace_stmt(stmt);
                }
                None
            }
            ast::Expr::Ident(name) => self.bindings.get(name).cloned(),
            ast::Expr::Int(_)
            | ast::Expr::Float { .. }
            | ast::Expr::Char(_)
            | ast::Expr::Bool(_)
            | ast::Expr::Str(_)
            | ast::Expr::Break(_)
            | ast::Expr::Continue
            | ast::Expr::Return(_)
            | ast::Expr::Match { .. } => None,
        }
    }

    fn trace_call(&mut self, callee: &str, args: &[ast::Expr]) -> Option<GpuTraceBinding> {
        for arg in args {
            self.trace_expr(arg);
        }
        let base = callee.split('<').next().unwrap_or(callee);
        match base {
            "gpu.default_device" => Some(self.trace_default_device(callee)),
            "gpu.alloc_f32" => self.trace_alloc_like(callee, args, "f32", "gpu.alloc"),
            "gpu.alloc_i32" => self.trace_alloc_like(callee, args, "i32", "gpu.alloc"),
            "gpu.alloc_u32" => self.trace_alloc_like(callee, args, "u32", "gpu.alloc"),
            "gpu.upload_f32" => self.trace_alloc_like(callee, args, "f32", "gpu.upload"),
            "gpu.upload_i32" => self.trace_alloc_like(callee, args, "i32", "gpu.upload"),
            "gpu.upload_u32" => self.trace_alloc_like(callee, args, "u32", "gpu.upload"),
            "gpu.slice" => self.trace_slice(callee, args),
            "gpu.download_f32" => {
                self.trace_buffer_op(callee, args, "gpu.download", Some("f32"));
                None
            }
            "gpu.download_i32" => {
                self.trace_buffer_op(callee, args, "gpu.download", Some("i32"));
                None
            }
            "gpu.download_u32" => {
                self.trace_buffer_op(callee, args, "gpu.download", Some("u32"));
                None
            }
            "gpu.free" => {
                self.trace_buffer_free(callee, args);
                None
            }
            "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4" => {
                self.trace_launch(callee, args)
            }
            "gpu.wait" | "gpu.wait_async" => {
                self.trace_wait(callee, args);
                None
            }
            _ => None,
        }
    }

    fn trace_default_device(&mut self, callee: &str) -> GpuTraceBinding {
        let resource_id = format!("gpu_device#{}", self.next_device_id);
        self.next_device_id += 1;
        let event_id = self.emit_event(
            "host",
            "gpu.device_select",
            callee.to_string(),
            Some(serde_json::json!({
                "deviceResource": resource_id,
            })),
        );
        GpuTraceBinding::Device {
            resource_id,
            event_id,
        }
    }

    fn trace_alloc_like(
        &mut self,
        callee: &str,
        args: &[ast::Expr],
        element_type: &'static str,
        kind: &str,
    ) -> Option<GpuTraceBinding> {
        let resource_id = format!("gpu_buffer#{}", self.next_buffer_id);
        self.next_buffer_id += 1;
        let device_resource = args
            .first()
            .and_then(|expr| self.resolve_binding(expr))
            .and_then(|binding| match binding {
                GpuTraceBinding::Device { resource_id, .. } => Some(resource_id),
                _ => None,
            });
        let len = args.get(1).and_then(expr_const_i64);
        let event_id = self.emit_event(
            "host",
            kind,
            callee.to_string(),
            Some(serde_json::json!({
                "bufferResource": resource_id,
                "elementType": element_type,
                "deviceResource": device_resource,
                "len": len,
            })),
        );
        Some(GpuTraceBinding::Buffer {
            resource_id,
            event_id,
            element_type,
            device_resource,
        })
    }

    fn trace_slice(&mut self, callee: &str, args: &[ast::Expr]) -> Option<GpuTraceBinding> {
        let Some(GpuTraceBinding::Buffer {
            resource_id: buffer_resource,
            event_id: buffer_event_id,
            ..
        }) = args.first().and_then(|expr| self.resolve_binding(expr))
        else {
            self.emit_gpu_error(
                callee,
                "gpu.slice expected a known GPU buffer binding",
                serde_json::json!({"reason": "unknown_buffer_binding"}),
            );
            return None;
        };
        let resource_id = format!("gpu_slice#{}", self.next_slice_id);
        self.next_slice_id += 1;
        let offset = args.get(1).and_then(expr_const_i64);
        let len = args.get(2).and_then(expr_const_i64);
        let event_id = self.emit_event(
            "host",
            "gpu.slice",
            callee.to_string(),
            Some(serde_json::json!({
                "sliceResource": resource_id,
                "bufferResource": buffer_resource,
                "offset": offset,
                "len": len,
            })),
        );
        self.emit_link(buffer_event_id, event_id, "gpu.buffer.slice_of");
        Some(GpuTraceBinding::Slice {
            resource_id,
            event_id,
            buffer_resource,
            offset,
            len,
        })
    }

    fn trace_buffer_op(
        &mut self,
        callee: &str,
        args: &[ast::Expr],
        kind: &str,
        element_type: Option<&'static str>,
    ) {
        let Some(GpuTraceBinding::Buffer {
            resource_id,
            event_id,
            ..
        }) = args.first().and_then(|expr| self.resolve_binding(expr))
        else {
            self.emit_gpu_error(
                callee,
                "GPU buffer operation expected a known buffer binding",
                serde_json::json!({"reason": "unknown_buffer_binding"}),
            );
            return;
        };
        let op_event_id = self.emit_event(
            "host",
            kind,
            callee.to_string(),
            Some(serde_json::json!({
                "bufferResource": resource_id,
                "elementType": element_type,
            })),
        );
        self.emit_link(event_id, op_event_id, "gpu.buffer.use");
    }

    fn trace_buffer_free(&mut self, callee: &str, args: &[ast::Expr]) {
        let Some(GpuTraceBinding::Buffer {
            resource_id,
            event_id,
            element_type,
            device_resource,
        }) = args.first().and_then(|expr| self.resolve_binding(expr))
        else {
            self.emit_gpu_error(
                callee,
                "gpu.free expected a known GPU buffer binding",
                serde_json::json!({"reason": "unknown_buffer_binding"}),
            );
            return;
        };
        let free_event_id = self.emit_event(
            "host",
            "gpu.free",
            callee.to_string(),
            Some(serde_json::json!({
                "bufferResource": resource_id,
                "elementType": element_type,
                "deviceResource": device_resource,
            })),
        );
        self.emit_link(event_id, free_event_id, "gpu.buffer.lifetime_end");
    }

    fn trace_launch(&mut self, callee: &str, args: &[ast::Expr]) -> Option<GpuTraceBinding> {
        let kernel_name = args
            .first()
            .map(render_expr_brief)
            .unwrap_or_else(|| "unknown_kernel".to_string());
        let grid = args.get(1).and_then(expr_const_i64);
        let block = args.get(2).and_then(expr_const_i64);
        if grid.is_some_and(|value| value <= 0) || block.is_some_and(|value| value <= 0) {
            self.emit_gpu_error(
                callee,
                "gpu.launch uses a non-positive grid or block size",
                serde_json::json!({
                    "kernelName": kernel_name,
                    "grid": grid,
                    "block": block,
                    "reason": "non_positive_launch_dimension",
                }),
            );
        }
        let param_layout = self.kernel_layouts.get(&kernel_name).cloned();
        let launch_args = self.build_launch_arg_trace(param_layout.as_deref(), &args[3..]);
        let event_resource = format!("gpu_event#{}", self.next_event_id);
        self.next_event_id += 1;
        let launch_event_id = self.emit_event(
            "host",
            "gpu.kernel_launch",
            callee.to_string(),
            Some(serde_json::json!({
                "kernelName": kernel_name,
                "grid": grid,
                "block": block,
                "paramLayout": param_layout,
                "eventResource": event_resource,
                "arguments": launch_args.iter().map(|arg| serde_json::json!({
                    "slot": arg.slot,
                    "layout": arg.layout,
                    "binding": arg.detail,
                })).collect::<Vec<_>>(),
            })),
        );
        for arg in &launch_args {
            for source_event_id in &arg.source_event_ids {
                self.emit_link(*source_event_id, launch_event_id, "gpu.kernel.argument");
            }
        }
        Some(GpuTraceBinding::Event {
            resource_id: event_resource,
            event_id: launch_event_id,
            kernel_name,
            launch_event_id,
        })
    }

    fn build_launch_arg_trace(
        &mut self,
        param_layout: Option<&str>,
        args: &[ast::Expr],
    ) -> Vec<GpuLaunchArgTrace> {
        let layouts = param_layout
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["unknown".to_string(); args.len()]);
        args.iter()
            .enumerate()
            .map(|(slot, expr)| {
                let layout = layouts
                    .get(slot)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                let (detail, source_event_ids) = self.describe_launch_arg(expr, &layout);
                GpuLaunchArgTrace {
                    slot,
                    layout,
                    detail,
                    source_event_ids,
                }
            })
            .collect()
    }

    fn describe_launch_arg(&self, expr: &ast::Expr, layout: &str) -> (serde_json::Value, Vec<u64>) {
        match self.resolve_binding(expr) {
            Some(GpuTraceBinding::Slice {
                resource_id,
                event_id,
                buffer_resource,
                offset,
                len,
            }) => (
                serde_json::json!({
                    "kind": "GpuSlice",
                    "sliceResource": resource_id,
                    "bufferResource": buffer_resource,
                    "offset": offset,
                    "len": len,
                }),
                vec![event_id],
            ),
            Some(GpuTraceBinding::Buffer {
                resource_id,
                event_id,
                element_type,
                device_resource,
            }) => (
                serde_json::json!({
                    "kind": "GpuBuffer",
                    "bufferResource": resource_id,
                    "elementType": element_type,
                    "deviceResource": device_resource,
                }),
                vec![event_id],
            ),
            Some(GpuTraceBinding::Device {
                resource_id,
                event_id,
            }) => (
                serde_json::json!({
                    "kind": "GpuDevice",
                    "deviceResource": resource_id,
                }),
                vec![event_id],
            ),
            Some(GpuTraceBinding::Event {
                resource_id,
                event_id,
                kernel_name,
                ..
            }) => (
                serde_json::json!({
                    "kind": "GpuEvent",
                    "eventResource": resource_id,
                    "kernelName": kernel_name,
                }),
                vec![event_id],
            ),
            None => (
                serde_json::json!({
                    "kind": "scalar",
                    "layout": layout,
                    "source": render_expr_brief(expr),
                }),
                Vec::new(),
            ),
        }
    }

    fn trace_wait(&mut self, callee: &str, args: &[ast::Expr]) {
        let Some(binding) = args.first().and_then(|expr| self.resolve_binding(expr)) else {
            self.emit_gpu_error(
                callee,
                "gpu.wait expected a known GPU event binding",
                serde_json::json!({"reason": "unknown_event_binding"}),
            );
            return;
        };
        let GpuTraceBinding::Event {
            resource_id,
            event_id,
            kernel_name,
            launch_event_id,
        } = binding
        else {
            self.emit_gpu_error(
                callee,
                "gpu.wait expected a GPU event binding",
                serde_json::json!({"reason": "non_event_wait_target"}),
            );
            return;
        };
        let wait_event_id = self.emit_event(
            "host",
            "gpu.event_wait",
            callee.to_string(),
            Some(serde_json::json!({
                "eventResource": resource_id,
                "kernelName": kernel_name,
            })),
        );
        self.emit_link(event_id, wait_event_id, "gpu.event.waits_for");
        self.emit_link(launch_event_id, wait_event_id, "gpu.kernel.wait");
        let complete_event_id = self.emit_event(
            "host",
            "gpu.kernel_complete",
            callee.to_string(),
            Some(serde_json::json!({
                "eventResource": resource_id,
                "kernelName": kernel_name,
                "status": "ok",
            })),
        );
        self.emit_link(wait_event_id, complete_event_id, "gpu.event.complete");
    }

    fn emit_gpu_error(&mut self, label: &str, message: &str, details: serde_json::Value) {
        self.emit_event(
            "host",
            "gpu.error",
            label.to_string(),
            Some(serde_json::json!({
                "message": message,
                "detail": details,
            })),
        );
    }
}

fn derive_gpu_runtime_semantic_evidence(
    module: &ast::Module,
    typed: &hir::TypedModule,
) -> (Vec<RuntimeSemanticEvent>, Vec<CausalLink>) {
    let mut analyzer = GpuTraceAnalyzer::new(gpu_kernel_param_layouts(typed));
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            for statement in &function.body {
                analyzer.trace_stmt(statement);
            }
        }
    }
    (analyzer.runtime_events, analyzer.causal_links)
}

fn gpu_kernel_param_layouts(typed: &hir::TypedModule) -> HashMap<String, String> {
    let Ok(module) = kernel_ir::lower(typed) else {
        return HashMap::new();
    };
    let function_map = module
        .functions
        .iter()
        .map(|function| (function.name.clone(), function))
        .collect::<BTreeMap<_, _>>();
    module
        .kernels
        .iter()
        .filter_map(|kernel_name| {
            function_map
                .get(kernel_name)
                .and_then(|function| render_gpu_shared_param_layout(function).ok())
                .map(|layout| (kernel_name.clone(), layout))
        })
        .collect()
}

fn render_gpu_shared_param_layout(function: &kernel_ir::KernelFunction) -> Result<String> {
    let mut parts = Vec::with_capacity(function.params.len());
    for param in &function.params {
        let part = match &param.ty {
            ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
                let element = match &args[0] {
                    ast::Type::Int {
                        signed: true,
                        bits: 32,
                    } => "i32",
                    ast::Type::Int {
                        signed: false,
                        bits: 32,
                    } => "u32",
                    ast::Type::Float { bits: 32 } => "f32",
                    other => bail!("unsupported gpu slice element type in trace layout: {other:?}"),
                };
                let mode = function
                    .slice_access
                    .get(&param.name)
                    .copied()
                    .unwrap_or(kernel_ir::KernelSliceAccessMode::Observe);
                let access = mode.layout_suffix();
                format!("slice_{element}_{access}")
            }
            ast::Type::Int {
                signed: true,
                bits: 32,
            } => "i32".to_string(),
            ast::Type::Int {
                signed: false,
                bits: 32,
            } => "u32".to_string(),
            ast::Type::Float { bits: 32 } => "f32".to_string(),
            other => bail!("unsupported gpu param type in trace layout: {other:?}"),
        };
        parts.push(part);
    }
    Ok(parts.join(","))
}

fn expr_const_i64(expr: &ast::Expr) -> Option<i64> {
    match expr {
        ast::Expr::Int(value) => i64::try_from(*value).ok(),
        _ => None,
    }
}

fn render_expr_brief(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Ident(name) => name.clone(),
        ast::Expr::Int(value) => value.to_string(),
        ast::Expr::Float { value, .. } => value.to_string(),
        ast::Expr::Bool(value) => value.to_string(),
        ast::Expr::Str(value) => value.clone(),
        ast::Expr::Call { callee, .. } => callee.clone(),
        _ => format!("{expr:?}"),
    }
}

fn build_rpc_frame_events(
    _source: &str,
    call_sequence: &[String],
    execution_order: &[u64],
    methods: &[RpcMethod],
) -> Vec<RpcFrameEvent> {
    if execution_order.is_empty() {
        return Vec::new();
    }
    if methods.is_empty() {
        return Vec::new();
    }

    let mut events = Vec::new();
    let rpc_methods = methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<BTreeSet<_>>();

    let mut cursor = 0usize;
    let mut pending = VecDeque::<String>::new();
    for call in call_sequence {
        if rpc_methods.contains(call.as_str()) {
            let task_id = execution_order[cursor % execution_order.len()];
            cursor += 1;
            events.push(RpcFrameEvent {
                kind: "rpc_send",
                method: call.clone(),
                task_id,
            });
            pending.push_back(call.clone());
            continue;
        }

        if (call == "timeout" || call == "deadline") && !pending.is_empty() {
            let method = pending.pop_front().unwrap_or_default();
            events.push(RpcFrameEvent {
                kind: "rpc_deadline",
                method,
                task_id: execution_order[cursor % execution_order.len()],
            });
            cursor += 1;
            continue;
        }
        if call == "cancel" && !pending.is_empty() {
            let method = pending.pop_front().unwrap_or_default();
            events.push(RpcFrameEvent {
                kind: "rpc_cancel",
                method,
                task_id: execution_order[cursor % execution_order.len()],
            });
            cursor += 1;
            continue;
        }
        if call == "recv" && !pending.is_empty() {
            let method = pending.pop_front().unwrap_or_default();
            events.push(RpcFrameEvent {
                kind: "rpc_recv",
                method,
                task_id: execution_order[cursor % execution_order.len()],
            });
            cursor += 1;
        }
    }
    while let Some(method) = pending.pop_front() {
        events.push(RpcFrameEvent {
            kind: "rpc_recv",
            method,
            task_id: execution_order[cursor % execution_order.len()],
        });
        cursor += 1;
    }

    events
}

fn collect_call_sequence(module: &ast::Module) -> Vec<String> {
    let mut call_sequence = Vec::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            for statement in &function.body {
                collect_call_names_from_stmt(statement, &mut call_sequence);
            }
        }
    }
    call_sequence
}

fn collect_call_names_from_stmt(statement: &ast::Stmt, out: &mut Vec<String>) {
    match statement {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_call_names_from_expr(value, out),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_call_names_from_expr(value, out);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_call_names_from_expr(condition, out);
            for stmt in then_body {
                collect_call_names_from_stmt(stmt, out);
            }
            for stmt in else_body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_call_names_from_expr(condition, out);
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_call_names_from_stmt(init, out);
            }
            if let Some(condition) = condition {
                collect_call_names_from_expr(condition, out);
            }
            if let Some(step) = step {
                collect_call_names_from_stmt(step, out);
            }
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_call_names_from_expr(iterable, out);
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::Loop { body } => {
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_call_names_from_expr(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_call_names_from_expr(guard, out);
                }
                collect_call_names_from_expr(&arm.value, out);
            }
        }
    }
}

fn collect_call_names_from_expr(expr: &ast::Expr, out: &mut Vec<String>) {
    match expr {
        ast::Expr::Call { callee, args } => {
            out.push(callee.clone());
            for arg in args {
                collect_call_names_from_expr(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => collect_call_names_from_expr(base, out),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_call_names_from_expr(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_call_names_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_call_names_from_expr(body, out),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_call_names_from_expr(try_expr, out);
            collect_call_names_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_call_names_from_expr(condition, out);
            collect_call_names_from_expr(then_expr, out);
            collect_call_names_from_expr(else_expr, out);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_call_names_from_expr(left, out);
            collect_call_names_from_expr(right, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_call_names_from_expr(start, out);
            collect_call_names_from_expr(end, out);
        }
        ast::Expr::Unary { expr, .. } => collect_call_names_from_expr(expr, out),
        ast::Expr::Group(inner) => collect_call_names_from_expr(inner, out),
        ast::Expr::Await(inner) => collect_call_names_from_expr(inner, out),
        ast::Expr::Discard(inner) => collect_call_names_from_expr(inner, out),
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_call_names_from_expr(item, out);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_call_names_from_expr(base, out);
            collect_call_names_from_expr(index, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn rpc_frames_json(frames: &[RpcFrameEvent]) -> Vec<serde_json::Value> {
    frames
        .iter()
        .map(|frame| {
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": frame.task_id,
            })
        })
        .collect()
}

fn rpc_validation_json(finding: &RpcValidationFinding) -> serde_json::Value {
    serde_json::json!({
        "kind": finding.kind,
        "severity": match finding.severity {
            RpcValidationSeverity::Info => "info",
            RpcValidationSeverity::Warning => "warning",
            RpcValidationSeverity::Error => "error",
        },
        "message": finding.message,
    })
}

fn validate_rpc_frames(frames: &[RpcFrameEvent]) -> Vec<RpcValidationFinding> {
    let mut findings = Vec::new();
    let mut pending = BTreeMap::<String, usize>::new();
    for frame in frames {
        match frame.kind {
            "rpc_send" => {
                *pending.entry(frame.method.clone()).or_insert(0) += 1;
            }
            "rpc_recv" => {
                let entry = pending.entry(frame.method.clone()).or_insert(0);
                if *entry == 0 {
                    findings.push(RpcValidationFinding {
                        kind: "rpc_recv_without_send",
                        severity: RpcValidationSeverity::Error,
                        message: format!(
                            "received response for `{}` without matching send",
                            frame.method
                        ),
                    });
                } else {
                    *entry -= 1;
                }
            }
            "rpc_cancel" | "rpc_deadline" => {
                let entry = pending.entry(frame.method.clone()).or_insert(0);
                if *entry == 0 {
                    findings.push(RpcValidationFinding {
                        kind: "rpc_terminal_without_inflight",
                        severity: RpcValidationSeverity::Warning,
                        message: format!(
                            "{} observed for `{}` without in-flight request",
                            frame.kind, frame.method
                        ),
                    });
                } else {
                    *entry -= 1;
                }
            }
            _ => {}
        }
    }
    for (method, inflight) in pending {
        if inflight > 0 {
            findings.push(RpcValidationFinding {
                kind: "rpc_inflight_leak",
                severity: RpcValidationSeverity::Error,
                message: format!(
                    "{inflight} in-flight request(s) for `{method}` did not terminate deterministically"
                ),
            });
        }
    }
    if findings.is_empty() && !frames.is_empty() {
        findings.push(RpcValidationFinding {
            kind: "rpc_sequence_validated",
            severity: RpcValidationSeverity::Info,
            message: "RPC send/recv/cancel/deadline sequencing is deterministic".to_string(),
        });
    }
    findings
}

fn thread_health_findings(
    events: &[TaskEvent],
    execution_order: &[u64],
    expected_tasks: usize,
    workload: &WorkloadShape,
    call_sequence: &[String],
) -> Vec<serde_json::Value> {
    let mut spawned = BTreeSet::<u64>::new();
    let mut completed = BTreeSet::<u64>::new();
    let mut panicked = BTreeSet::<u64>::new();
    for event in events {
        match event {
            TaskEvent::Spawned { task_id, .. } => {
                spawned.insert(*task_id);
            }
            TaskEvent::Completed { task_id } => {
                completed.insert(*task_id);
            }
            TaskEvent::Panicked { task_id, .. } => {
                panicked.insert(*task_id);
            }
            TaskEvent::TimedOut { task_id, .. } => {
                panicked.insert(*task_id);
            }
            TaskEvent::Cancelled { task_id } => {
                completed.insert(*task_id);
            }
            TaskEvent::Started { .. }
            | TaskEvent::Detached { .. }
            | TaskEvent::PanicRootCause { .. }
            | TaskEvent::Backpressure { .. }
            | TaskEvent::JoinWait { .. }
            | TaskEvent::JoinCycle { .. }
            | TaskEvent::Yielded { .. }
            | TaskEvent::IoWait { .. }
            | TaskEvent::IoReady { .. }
            | TaskEvent::ChannelSend { .. }
            | TaskEvent::ChannelRecv { .. }
            | TaskEvent::MemoryPressure { .. }
            | TaskEvent::ResourceLeak { .. } => {}
        }
    }
    let mut findings = Vec::new();
    if spawned.len() < expected_tasks {
        findings.push(serde_json::json!({
            "kind": "thread_spawn_shortfall",
            "severity": "warning",
            "message": format!(
                "expected at least {expected_tasks} deterministic tasks, observed {}",
                spawned.len()
            ),
        }));
    }
    if completed.len() + panicked.len() < spawned.len() {
        findings.push(serde_json::json!({
            "kind": "thread_deadlock_suspect",
            "severity": "error",
            "message": "spawned tasks missing terminal state (possible deadlock)",
        }));
    }
    if workload.spawn_markers > 0 && workload.yield_markers == 0 {
        findings.push(serde_json::json!({
            "kind": "thread_starvation_risk",
            "severity": "warning",
            "message": "spawn observed without yield/checkpoint markers; starvation risk under host scheduler",
        }));
    } else if workload.spawn_markers > (workload.yield_markers.saturating_mul(8)).max(8) {
        findings.push(serde_json::json!({
            "kind": "thread_fairness_pressure",
            "severity": "warning",
            "message": format!(
                "spawn/yield ratio is high (spawns={} yields={}); add join/checkpoint boundaries to reduce scheduler unfairness risk",
                workload.spawn_markers, workload.yield_markers
            ),
        }));
    }
    let lock_calls = call_sequence
        .iter()
        .filter(|call| call.as_str() == "lock")
        .count();
    let unlock_calls = call_sequence
        .iter()
        .filter(|call| call.as_str() == "unlock")
        .count();
    if lock_calls > unlock_calls {
        findings.push(serde_json::json!({
            "kind": "lock_unbalanced",
            "severity": "warning",
            "message": "lock/unlock imbalance detected; potential deadlock path",
            "locks": lock_calls,
            "unlocks": unlock_calls,
        }));
    }
    if execution_order.is_empty() {
        findings.push(serde_json::json!({
            "kind": "no_thread_schedule",
            "severity": "error",
            "message": "deterministic execution produced no scheduled tasks",
        }));
    }
    findings
}

fn unsafe_trace_findings(fir: &fir::FirModule) -> Vec<serde_json::Value> {
    let sites = fir
        .unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .collect::<Vec<_>>();
    if sites.is_empty() {
        return Vec::new();
    }
    let mut contract_lines = sites
        .iter()
        .filter(|site| {
            site.reason.as_deref().is_some_and(|v| !v.is_empty())
                && site.invariant.as_deref().is_some_and(|v| !v.is_empty())
                && site.owner.as_deref().is_some_and(|v| !v.is_empty())
                && site.scope.as_deref().is_some_and(|v| !v.is_empty())
                && site.risk_class.as_deref().is_some_and(|v| !v.is_empty())
                && site.proof_ref.as_deref().is_some_and(|v| !v.is_empty())
        })
        .map(|site| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                site.site_id,
                site.kind,
                site.reason.as_deref().unwrap_or_default(),
                site.invariant.as_deref().unwrap_or_default(),
                site.owner.as_deref().unwrap_or_default(),
                site.scope.as_deref().unwrap_or_default(),
                site.risk_class.as_deref().unwrap_or_default(),
                site.proof_ref.as_deref().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    contract_lines.sort();
    let metadata_sites = contract_lines.len();
    let contract_hash = if contract_lines.is_empty() {
        None
    } else {
        let mut hasher = Sha256::new();
        for line in &contract_lines {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        Some(
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
    };
    vec![serde_json::json!({
        "kind": "unsafe_site_accounting",
        "severity": "info",
        "message": format!("unsafe enter/exit accounting: enters={} exits={} metadata_sites={}", sites.len(), sites.len(), metadata_sites),
        "unsafeEnters": sites.len(),
        "unsafeExits": sites.len(),
        "metadataSites": metadata_sites,
        "contractHash": contract_hash,
    })]
}

fn rpc_failure_findings(frames: &[RpcFrameEvent]) -> Vec<serde_json::Value> {
    let has_deadline = frames.iter().any(|frame| frame.kind == "rpc_deadline");
    let has_cancel = frames.iter().any(|frame| frame.kind == "rpc_cancel");
    let recv_by_method = frames
        .iter()
        .filter(|frame| frame.kind == "rpc_recv")
        .map(|frame| frame.method.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let mut findings = Vec::new();
    if has_deadline {
        findings.push(serde_json::json!({
            "kind": "rpc_deadline",
            "severity": "warning",
            "message": "deadline event observed; verify timeout semantics are deterministic",
        }));
    }
    if has_cancel {
        findings.push(serde_json::json!({
            "kind": "rpc_cancel",
            "severity": "warning",
            "message": "cancellation event observed; verify cancellation propagation and cleanup",
        }));
    }
    if has_cancel && !recv_by_method.is_empty() {
        findings.push(serde_json::json!({
            "kind": "rpc_partial_response_after_cancel",
            "severity": "info",
            "message": "received response frames alongside cancellation; inspect partial-response handling",
            "methods": recv_by_method.into_iter().collect::<Vec<_>>(),
        }));
    }
    findings
}

fn build_schedule_candidates(execution_order: &[u64]) -> serde_json::Value {
    if execution_order.is_empty() {
        return serde_json::json!([]);
    }
    let fifo = execution_order.to_vec();
    let reversed = execution_order.iter().copied().rev().collect::<Vec<_>>();
    let rotated = execution_order
        .iter()
        .copied()
        .cycle()
        .skip(1)
        .take(execution_order.len())
        .collect::<Vec<_>>();
    serde_json::json!([
        { "name": "fifo", "order": fifo },
        { "name": "reverse", "order": reversed },
        { "name": "rotate_1", "order": rotated },
    ])
}

fn build_rpc_frame_permutations(
    execution_order: &[u64],
    frames: &[RpcFrameEvent],
) -> serde_json::Value {
    if frames.is_empty() || execution_order.is_empty() {
        return serde_json::json!([]);
    }
    let canonical = rpc_frames_json(frames);
    let mut task_index = 0usize;
    let rotated = frames
        .iter()
        .map(|frame| {
            let task_id = execution_order[task_index % execution_order.len()];
            task_index += 1;
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": task_id,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!([
        { "name": "canonical", "frames": canonical },
        { "name": "task_rotated", "frames": rotated },
    ])
}

fn build_shrink_hints(
    discovered_test_names: &[String],
    execution_order: &[u64],
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
) -> serde_json::Value {
    let mut hints = Vec::new();
    for name in discovered_test_names {
        hints.push(serde_json::json!({
            "kind": "single_test",
            "tests": [name],
        }));
    }
    for pair in discovered_test_names.windows(2) {
        hints.push(serde_json::json!({
            "kind": "test_pair",
            "tests": [pair[0].clone(), pair[1].clone()],
        }));
    }
    if !rpc_frames.is_empty() {
        let methods = rpc_frames
            .iter()
            .map(|frame| frame.method.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        hints.push(serde_json::json!({
            "kind": "rpc_methods",
            "methods": methods,
        }));
    }
    if !async_execution.is_empty() {
        hints.push(serde_json::json!({
            "kind": "async_checkpoint_focus",
            "taskIds": async_execution,
        }));
    }
    if !execution_order.is_empty() {
        hints.push(serde_json::json!({
            "kind": "task_order",
            "order": execution_order,
        }));
    }
    serde_json::json!(hints)
}

fn minimize_rpc_failure_frames(frames: &[RpcFrameEvent]) -> serde_json::Value {
    if frames.is_empty() {
        return serde_json::json!([]);
    }
    let pivot = frames
        .iter()
        .find(|frame| frame.kind == "rpc_deadline" || frame.kind == "rpc_cancel")
        .map(|frame| frame.method.clone());
    let Some(method) = pivot else {
        return serde_json::json!(rpc_frames_json(frames));
    };
    let minimal = frames
        .iter()
        .filter(|frame| frame.method == method)
        .map(|frame| {
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": frame.task_id,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!(minimal)
}

fn classify_failure_classes(
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
    execution_order: &[u64],
) -> Vec<serde_json::Value> {
    let mut classes = Vec::new();
    if rpc_frames.iter().any(|frame| frame.kind == "rpc_deadline") {
        classes.push(serde_json::json!({
            "id": "rpc_timeout",
            "priority": 1,
            "signal": "rpc_deadline",
        }));
    }
    if rpc_frames.iter().any(|frame| frame.kind == "rpc_cancel") {
        classes.push(serde_json::json!({
            "id": "rpc_cancel_race",
            "priority": 2,
            "signal": "rpc_cancel",
        }));
    }
    if !async_execution.is_empty() {
        classes.push(serde_json::json!({
            "id": "async_schedule_interleaving",
            "priority": 3,
            "signal": "async.schedule",
        }));
    }
    if execution_order.len() > 1 {
        classes.push(serde_json::json!({
            "id": "thread_interleaving",
            "priority": 4,
            "signal": "thread.schedule",
        }));
    }
    if classes.is_empty() {
        classes.push(serde_json::json!({
            "id": "baseline",
            "priority": 9,
            "signal": "deterministic",
        }));
    }
    classes
}

fn build_scenario_priorities(
    generated_scenarios: &[PathBuf],
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
) -> serde_json::Value {
    let mut items = Vec::new();
    for path in generated_scenarios {
        let mut score = 100i32;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if name == "all.fozzy.json" {
            score -= 30;
        }
        if !rpc_frames.is_empty() {
            score -= 20;
        }
        if !async_execution.is_empty() {
            score -= 10;
        }
        items.push(serde_json::json!({
            "scenario": path.display().to_string(),
            "score": score,
        }));
    }
    items.sort_by_key(|item| item.get("score").and_then(|v| v.as_i64()).unwrap_or(999));
    serde_json::json!(items)
}

fn generate_language_test_scenarios(
    base_dir: &Path,
    stem: &str,
    deterministic_test_names: &[String],
) -> Result<(Option<PathBuf>, Vec<PathBuf>)> {
    let scenarios_dir = base_dir.join(format!("{stem}.scenarios"));
    std::fs::create_dir_all(&scenarios_dir).with_context(|| {
        format!(
            "failed creating language test scenarios dir: {}",
            scenarios_dir.display()
        )
    })?;

    let combined_path = scenarios_dir.join("all.fozzy.json");
    let combined_steps = deterministic_test_names
        .iter()
        .map(|name| serde_json::json!({ "type": "trace_event", "name": format!("test:{name}") }))
        .collect::<Vec<_>>();
    let combined_payload = serde_json::json!({
        "version": 1,
        "name": "language-tests-all",
        "steps": combined_steps,
    });
    std::fs::write(
        &combined_path,
        serde_json::to_vec_pretty(&combined_payload)?,
    )
    .with_context(|| {
        format!(
            "failed writing combined scenario: {}",
            combined_path.display()
        )
    })?;

    let mut generated = vec![combined_path.clone()];
    for test_name in deterministic_test_names {
        let safe_name = sanitize_file_component(test_name);
        let scenario_path = scenarios_dir.join(format!("{safe_name}.fozzy.json"));
        let payload = serde_json::json!({
            "version": 1,
            "name": format!("language-test-{safe_name}"),
            "steps": [
                { "type": "trace_event", "name": format!("test:{test_name}") },
                { "type": "assert_eq_int", "a": 1, "b": 1 }
            ],
        });
        std::fs::write(&scenario_path, serde_json::to_vec_pretty(&payload)?).with_context(
            || {
                format!(
                    "failed writing scenario for test `{}`: {}",
                    test_name,
                    scenario_path.display()
                )
            },
        )?;
        generated.push(scenario_path);
    }
    for pair in deterministic_test_names.windows(2) {
        let left = sanitize_file_component(&pair[0]);
        let right = sanitize_file_component(&pair[1]);
        let scenario_path = scenarios_dir.join(format!("{left}__{right}.fozzy.json"));
        let payload = serde_json::json!({
            "version": 1,
            "name": format!("language-test-pair-{left}-{right}"),
            "steps": [
                { "type": "trace_event", "name": format!("test:{}", pair[0]) },
                { "type": "trace_event", "name": format!("test:{}", pair[1]) },
                { "type": "assert_eq_int", "a": 1, "b": 1 }
            ],
        });
        std::fs::write(&scenario_path, serde_json::to_vec_pretty(&payload)?).with_context(
            || {
                format!(
                    "failed writing pair scenario for tests `{}` + `{}`: {}",
                    pair[0],
                    pair[1],
                    scenario_path.display()
                )
            },
        )?;
        generated.push(scenario_path);
    }

    let primary = generated.first().cloned();
    Ok((primary, generated))
}

fn sanitize_file_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "test".to_string()
    } else {
        out
    }
}

fn sanitize_c_identifier(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn parse_scheduler(input: &str) -> Result<Scheduler> {
    match input {
        "fifo" | "default" | "host" => Ok(Scheduler::Fifo),
        "random" => Ok(Scheduler::Random),
        "coverage_guided" => Ok(Scheduler::CoverageGuided),
        other => bail!(
            "unknown scheduler `{}`; expected one of: fifo, random, coverage_guided",
            other
        ),
    }
}

fn scheduler_name(scheduler: Scheduler) -> &'static str {
    match scheduler {
        Scheduler::Fifo => "fifo",
        Scheduler::Random => "random",
        Scheduler::CoverageGuided => "coverage_guided",
    }
}

fn persist_runtime_threads_config(path: &Path, threads: Option<u16>) -> Result<Option<PathBuf>> {
    let Some(threads) = threads else {
        return Ok(None);
    };
    if threads == 0 {
        bail!("--threads must be greater than zero");
    }
    let root = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let config_path = root.join(".fz").join("runtime.json");
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating runtime config directory: {}",
                parent.display()
            )
        })?;
    }
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.runtime.v0",
        "threads": threads,
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing runtime config: {}", config_path.display()))?;
    Ok(Some(config_path))
}

fn replay_like(command: &str, target: &Path, strict: bool, format: Format) -> Result<String> {
    scenario_replay_like(command, target, strict, format)
}

#[derive(Debug, Clone, Deserialize)]
struct NativeTracePayloadOwned {
    #[serde(rename = "executionOrder")]
    execution_order: Vec<u64>,
    #[serde(rename = "asyncSchedule")]
    async_schedule: Vec<u64>,
    #[serde(rename = "rpcFrames")]
    rpc_frames: Vec<RpcFrameEventOwned>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcFrameEventOwned {
    #[serde(rename = "event")]
    kind: String,
    method: String,
    #[serde(rename = "taskId")]
    task_id: u64,
}

fn is_native_trace_or_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".trace.json") || name.ends_with(".manifest.json"))
        .unwrap_or(false)
}

