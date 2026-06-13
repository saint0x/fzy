impl Parser {
    fn at_ident(&self, expected: &str) -> bool {
        matches!(self.peek_kind(), TokenKind::Ident(value) if value.as_ref() == expected)
    }

    fn consume_ident(&mut self, expected: &str) -> bool {
        if self.at_ident(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn new(tokens: Vec<Token>, module_name: &str) -> Self {
        Self {
            tokens,
            pos: 0,
            diagnostics: Vec::new(),
            module: Module {
                name: module_name.to_string(),
                items: Vec::new(),
                modules: Vec::new(),
                imports: Vec::new(),
                capabilities: Vec::new(),
                host_syscall_sites: 0,
                unsafe_sites: 0,
                unsafe_reasoned_sites: 0,
                reference_sites: 0,
                alloc_sites: 0,
                free_sites: 0,
            },
            pending_repr: None,
            pending_ffi_panic: None,
        }
    }

    fn parse_module(&mut self) -> Module {
        while !self.at(&TokenKind::Eof) {
            let start = self.pos;
            if self.at(&TokenKind::Hash) {
                self.parse_attribute();
                continue;
            }
            match self.parse_item() {
                Some(item) => self.module.items.push(item),
                None => {
                    if self.pos == start {
                        self.recover_item();
                    }
                }
            }
        }
        std::mem::take(&mut self.module)
    }

    fn parse_attribute(&mut self) {
        let Some(hash) = self.advance() else {
            return;
        };
        if !self.consume(&TokenKind::LBracket) {
            self.push_diag_at(hash.line, hash.col, "expected `[` after `#`");
            return;
        }
        let Some(name_token) = self.advance() else {
            return;
        };
        let TokenKind::Ident(name) = &name_token.kind else {
            self.push_diag_at(name_token.line, name_token.col, "expected attribute name");
            return;
        };
        match name.as_ref() {
            "repr" => {
                if !self.consume(&TokenKind::LParen) {
                    self.push_diag_at(name_token.line, name_token.col, "expected `(` after `repr`");
                    return;
                }
                let mut parts = Vec::new();
                while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                    let Some(tok) = self.advance() else {
                        break;
                    };
                    match tok.kind {
                        TokenKind::Ident(part) => parts.push(part),
                        TokenKind::Comma => {}
                        _ => {
                            self.push_diag_at(tok.line, tok.col, "invalid repr attribute component")
                        }
                    }
                }
                let _ = self.consume(&TokenKind::RParen);
                let _ = self.consume(&TokenKind::RBracket);
                if !parts.is_empty() {
                    self.pending_repr = Some(parts.join(", "));
                }
            }
            "ffi_panic" => {
                if !self.consume(&TokenKind::LParen) {
                    self.push_diag_at(
                        name_token.line,
                        name_token.col,
                        "expected `(` after `ffi_panic`",
                    );
                    return;
                }
                let mode = match self.advance() {
                    Some(Token {
                        kind: TokenKind::Ident(mode),
                        ..
                    }) => mode,
                    Some(tok) => {
                        self.push_diag_at(tok.line, tok.col, "invalid ffi_panic mode");
                        Box::<str>::default()
                    }
                    None => Box::<str>::default(),
                };
                if !mode.is_empty() && mode.as_ref() != "abort" && mode.as_ref() != "error" {
                    self.push_diag_at(
                        name_token.line,
                        name_token.col,
                        "ffi_panic mode must be `abort` or `error`",
                    );
                } else if !mode.is_empty() {
                    self.pending_ffi_panic = Some(mode.to_string());
                }
                let _ = self.consume(&TokenKind::RParen);
                let _ = self.consume(&TokenKind::RBracket);
            }
            _ => {
                self.push_diag_at(name_token.line, name_token.col, "unsupported attribute");
                self.consume_until(&[TokenKind::RBracket]);
                let _ = self.consume(&TokenKind::RBracket);
            }
        }
    }

    fn parse_item(&mut self) -> Option<ast::Item> {
        if self.at(&TokenKind::KwPub) {
            match self.peek_n(1).map(|token| &token.kind) {
                Some(TokenKind::KwUse) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    self.parse_use_or_cap(true);
                    return None;
                }
                Some(TokenKind::KwMod) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    self.parse_mod_decl(true);
                    return None;
                }
                Some(TokenKind::KwConst) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_const(true);
                }
                Some(TokenKind::KwStatic) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_static(true);
                }
                Some(TokenKind::KwType) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_type_alias(true);
                }
                Some(TokenKind::KwNewtype) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_newtype(true);
                }
                Some(TokenKind::KwStruct) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_struct(true);
                }
                Some(TokenKind::KwEnum) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_enum(true);
                }
                Some(TokenKind::KwTrait) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_trait(true);
                }
                Some(TokenKind::KwImpl) => {
                    let _ = self.consume(&TokenKind::KwPub);
                    return self.parse_impl(true);
                }
                _ => {}
            }
        }
        if self.pending_ffi_panic.is_some()
            && !matches!(
                self.peek_kind(),
                &TokenKind::KwFn
                    | &TokenKind::KwAsync
                    | &TokenKind::KwUnsafe
                    | &TokenKind::KwHost
                    | &TokenKind::KwPure
                    | &TokenKind::KwDevice
                    | &TokenKind::KwKernel
                    | &TokenKind::KwPub
                    | &TokenKind::KwPubext
                    | &TokenKind::KwExt
            )
        {
            self.push_diag_here("`#[ffi_panic(...)]` applies only to functions");
            self.pending_ffi_panic = None;
        }
        if self.at(&TokenKind::KwUse) {
            self.parse_use_or_cap(false);
            return None;
        }
        if self.at(&TokenKind::KwMod) {
            self.parse_mod_decl(false);
            return None;
        }
        if self.at(&TokenKind::KwTest) {
            return self.parse_test();
        }
        if self.at(&TokenKind::KwStruct) {
            return self.parse_struct(false);
        }
        if self.at(&TokenKind::KwType) {
            return self.parse_type_alias(false);
        }
        if self.at(&TokenKind::KwNewtype) {
            return self.parse_newtype(false);
        }
        if self.at(&TokenKind::KwConst) {
            return self.parse_const(false);
        }
        if self.at(&TokenKind::KwStatic) {
            return self.parse_static(false);
        }
        if self.at(&TokenKind::KwEnum) {
            return self.parse_enum(false);
        }
        if self.at(&TokenKind::KwTrait) {
            return self.parse_trait(false);
        }
        if self.at(&TokenKind::KwImpl) {
            return self.parse_impl(false);
        }
        if self.at(&TokenKind::KwRpc) {
            self.parse_rpc_decl();
            return None;
        }
        self.parse_function()
    }

    fn parse_rpc_decl(&mut self) {
        let _ = self.consume(&TokenKind::KwRpc);
        let Some(name) = self.expect_ident("expected rpc method name") else {
            self.consume_until(&[TokenKind::Semi]);
            let _ = self.consume(&TokenKind::Semi);
            return;
        };
        if !self.consume(&TokenKind::LParen) {
            self.push_diag_here("expected `(` after rpc method name");
            self.consume_until(&[TokenKind::Semi]);
            let _ = self.consume(&TokenKind::Semi);
            return;
        }
        let mut params = Vec::new();
        let mut positional = 0usize;
        while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
            let (param_name, ty) = if matches!(self.peek_kind(), &TokenKind::Ident(_))
                && matches!(self.peek_n(1).map(|tok| &tok.kind), Some(TokenKind::Colon))
            {
                let Some(param_name) = self.expect_ident("expected rpc parameter name") else {
                    break;
                };
                let _ = self.consume(&TokenKind::Colon);
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                };
                (param_name, ty)
            } else {
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                };
                let name = format!("arg{positional}");
                positional += 1;
                (name, ty)
            };
            params.push(ast::Param {
                name: param_name,
                ty,
            });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        let _ = self.consume(&TokenKind::RParen);
        let return_type = if self.consume(&TokenKind::Arrow) {
            self.parse_type().unwrap_or(Type::Void)
        } else {
            Type::Void
        };
        let _ = self.consume(&TokenKind::Semi);
        let link_name = Some(name.clone());
        self.module.items.push(ast::Item::Function(ast::Function {
            name: name.to_string(),
            link_name,
            generics: Vec::new(),
            params,
            return_type,
            body: Vec::new(),
            is_unsafe: false,
            unsafe_meta: None,
            is_async: false,
            is_pub: false,
            is_pubext: false,
            is_extern: true,
            execution_space: ast::ExecutionSpace::Host,
            abi: Some("rpc".to_string()),
            ffi_panic: None,
        }));
    }

    fn parse_use_or_cap(&mut self, is_pub: bool) {
        let _ = self.consume(&TokenKind::KwUse);
        if !is_pub && self.consume(&TokenKind::KwCore) {
            if !self.consume(&TokenKind::Dot) {
                self.push_diag_here("expected `.` after `use core`");
                return;
            }
            let Some(name) = self.expect_ident("expected capability or stdlib module name") else {
                return;
            };
            if let Some(core_binding) = core_stdlib_binding(name.as_str()) {
                if let Some(capability) = core_stdlib_implied_capability(core_binding.name) {
                    self.module.capabilities.push(capability.to_string());
                }
                if let Some(module_name) = core_binding.module_name {
                    self.module.imports.push(ast::Import {
                        path: vec![module_name.to_string()],
                        alias: None,
                        is_pub: false,
                        wildcard: false,
                    });
                }
            } else {
                self.module.capabilities.push(name);
            }
            let _ = self.consume(&TokenKind::Semi);
            return;
        }
        let mut imports = Vec::new();
        if !self.parse_use_tree(None, &mut imports) {
            self.consume_until(&[TokenKind::Semi]);
        }
        while self.consume(&TokenKind::Comma) {
            if !self.parse_use_tree(None, &mut imports) {
                self.consume_until(&[TokenKind::Semi]);
                break;
            }
        }
        if is_pub {
            for import in &mut imports {
                import.is_pub = true;
            }
        }
        self.module.imports.extend(imports);
        let _ = self.consume(&TokenKind::Semi);
    }

    fn parse_use_tree(&mut self, prefix: Option<&[String]>, out: &mut Vec<ast::Import>) -> bool {
        let Some(local_path) = self.parse_import_path_segments() else {
            self.push_diag_here("expected import path");
            return false;
        };
        let full_path = if let Some(prefix) = prefix {
            prefix.iter().cloned().chain(local_path).collect::<Vec<_>>()
        } else {
            local_path
        };

        if self.consume_double_colon() {
            if self.consume(&TokenKind::Star) {
                out.push(ast::Import {
                    path: full_path,
                    alias: None,
                    is_pub: false,
                    wildcard: true,
                });
                return true;
            }
            if self.consume(&TokenKind::LBrace) {
                let mut saw_any = false;
                while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                    saw_any = true;
                    let parsed = self.parse_use_tree(Some(&full_path), out);
                    if !parsed {
                        self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                    }
                    if !self.consume(&TokenKind::Comma) {
                        break;
                    }
                }
                if !self.consume(&TokenKind::RBrace) {
                    self.push_diag_here("expected `}` to close grouped import");
                }
                if !saw_any {
                    self.push_diag_here("grouped import cannot be empty");
                }
                return true;
            }
            self.push_diag_here("expected `*`, `{`, or path segment after `::`");
            return false;
        }

        if self.consume_ident("as") {
            let Some(alias) = self.expect_ident("expected alias target after `as`") else {
                return false;
            };
            out.push(ast::Import {
                path: full_path,
                alias: Some(alias),
                is_pub: false,
                wildcard: false,
            });
            return true;
        }

        out.push(ast::Import {
            path: full_path,
            alias: None,
            is_pub: false,
            wildcard: false,
        });
        true
    }

    fn parse_import_path_segments(&mut self) -> Option<Vec<String>> {
        let mut path = vec![self.expect_ident("expected import path")?];
        while self.at_import_path_separator()
            && self
                .peek_after_import_path_separator()
                .is_some_and(|tok| matches!(tok.kind, TokenKind::Ident(_)))
        {
            let _ = self.consume_import_path_separator();
            let seg = self.expect_ident("expected import path segment")?;
            path.push(seg);
        }
        Some(path)
    }

    fn at_import_path_separator(&self) -> bool {
        self.at_double_colon() || self.at(&TokenKind::Dot)
    }

    fn peek_after_import_path_separator(&self) -> Option<&Token> {
        if self.at_double_colon() {
            self.peek_n(2)
        } else if self.at(&TokenKind::Dot) {
            self.peek_n(1)
        } else {
            None
        }
    }

    fn consume_import_path_separator(&mut self) -> bool {
        if self.consume_double_colon() {
            true
        } else {
            self.consume(&TokenKind::Dot)
        }
    }

    fn at_double_colon(&self) -> bool {
        self.at(&TokenKind::Colon)
            && self
                .peek_n(1)
                .is_some_and(|tok| tok.kind == TokenKind::Colon)
    }

    fn consume_double_colon(&mut self) -> bool {
        if self.at_double_colon() {
            let _ = self.advance();
            let _ = self.advance();
            true
        } else {
            false
        }
    }

    fn parse_mod_decl(&mut self, _is_pub: bool) {
        let _ = self.consume(&TokenKind::KwMod);
        let Some(name) = self.expect_ident("expected module name") else {
            return;
        };
        self.module.modules.push(name);
        let _ = self.consume(&TokenKind::Semi);
    }

    fn parse_test(&mut self) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwTest);
        let name = match self.advance()?.kind {
            TokenKind::Str(value) => value,
            _ => {
                self.push_diag_here("expected quoted test name");
                return None;
            }
        };
        let deterministic = !self.consume(&TokenKind::KwNondet);
        let body = if self.at(&TokenKind::LBrace) {
            self.parse_block()?
        } else {
            self.push_diag_here("expected `{` to start test body");
            return None;
        };
        Some(ast::Item::Test(ast::TestBlock {
            name: name.to_string(),
            deterministic,
            body,
        }))
    }

    fn parse_struct(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwStruct);
        let name = self.expect_ident("expected struct name")?;
        let generics = self.parse_generic_params();
        let mut fields = Vec::new();
        if self.consume(&TokenKind::LBrace) {
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                let field_name = match self.expect_ident("expected field name") {
                    Some(v) => v,
                    None => break,
                };
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in field declaration");
                    self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                }
                let field_ty = match self.parse_type() {
                    Some(ty) => ty,
                    None => {
                        self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                        let _ = self.consume(&TokenKind::Comma);
                        continue;
                    }
                };
                fields.push(ast::Field {
                    name: field_name,
                    ty: field_ty,
                });
                let _ = self.consume(&TokenKind::Comma);
            }
            let _ = self.consume(&TokenKind::RBrace);
        }
        Some(ast::Item::Struct(ast::Struct {
            name,
            generics,
            fields,
            repr: self.pending_repr.take(),
            is_pub,
        }))
    }

    fn parse_const(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwConst);
        let name = self.expect_ident("expected const name")?;
        if !self.consume(&TokenKind::Colon) {
            self.push_diag_here("expected `:` in const declaration");
            return None;
        }
        let ty = self.parse_type()?;
        if !self.consume(&TokenKind::Eq) {
            self.push_diag_here("expected `=` in const declaration");
            return None;
        }
        let value = self.parse_expr(0)?;
        let _ = self.consume(&TokenKind::Semi);
        Some(ast::Item::Const(ast::ConstItem {
            name,
            ty,
            value,
            is_pub,
        }))
    }

    fn parse_static(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwStatic);
        let mutable = self.consume_ident("mut");
        let name = self.expect_ident("expected static name")?;
        if !self.consume(&TokenKind::Colon) {
            self.push_diag_here("expected `:` in static declaration");
            return None;
        }
        let ty = self.parse_type()?;
        if !self.consume(&TokenKind::Eq) {
            self.push_diag_here("expected `=` in static declaration");
            return None;
        }
        let value = self.parse_expr(0)?;
        let _ = self.consume(&TokenKind::Semi);
        Some(ast::Item::Static(ast::StaticItem {
            name,
            ty,
            value,
            is_pub,
            mutable,
        }))
    }

    fn parse_type_alias(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwType);
        let name = self.expect_ident("expected type alias name")?;
        if !self.consume(&TokenKind::Eq) {
            self.push_diag_here("expected `=` in type alias declaration");
            return None;
        }
        let ty = self.parse_type()?;
        let _ = self.consume(&TokenKind::Semi);
        Some(ast::Item::TypeAlias(ast::TypeAlias { name, ty, is_pub }))
    }

    fn parse_newtype(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwNewtype);
        let name = self.expect_ident("expected newtype name")?;
        if !self.consume(&TokenKind::LParen) {
            self.push_diag_here("expected `(` in newtype declaration");
            return None;
        }
        let inner = self.parse_type()?;
        if !self.consume(&TokenKind::RParen) {
            self.push_diag_here("expected `)` in newtype declaration");
            return None;
        }
        let _ = self.consume(&TokenKind::Semi);
        let transparent = self
            .pending_repr
            .as_deref()
            .is_some_and(|repr| repr.split(',').any(|part| part.trim() == "transparent"));
        let _ = self.pending_repr.take();
        Some(ast::Item::NewType(ast::NewType {
            name,
            inner,
            transparent,
            is_pub,
        }))
    }

    fn parse_enum(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwEnum);
        let name = self.expect_ident("expected enum name")?;
        let generics = self.parse_generic_params();
        let mut variants = Vec::new();
        if self.consume(&TokenKind::LBrace) {
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                let Some(variant_name) = self.expect_ident("expected variant name") else {
                    break;
                };
                if self.at(&TokenKind::Colon)
                    && self
                        .peek_n(1)
                        .is_some_and(|tok| tok.kind == TokenKind::Colon)
                {
                    let _ = self.consume(&TokenKind::Colon);
                    let _ = self.consume(&TokenKind::Colon);
                    let _ = self.expect_ident("expected enum variant name");
                    self.push_diag_here(
                        "qualified enum declaration variant is not supported; declare bare variant names (for example: `Ping`) and use `Enum::Variant` at callsites/patterns",
                    );
                    self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                }
                let mut payload = Vec::new();
                let mut named_payload = Vec::new();
                if self.consume(&TokenKind::LParen) {
                    while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                        if let Some(ty) = self.parse_type() {
                            payload.push(ty);
                        }
                        if !self.consume(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let _ = self.consume(&TokenKind::RParen);
                } else if self.consume(&TokenKind::LBrace) {
                    while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                        let field_name = match self.expect_ident("expected field name") {
                            Some(v) => v,
                            None => break,
                        };
                        if !self.consume(&TokenKind::Colon) {
                            self.push_diag_here("expected `:` in enum struct-variant field");
                            self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                            let _ = self.consume(&TokenKind::Comma);
                            continue;
                        }
                        let field_ty = match self.parse_type() {
                            Some(ty) => ty,
                            None => {
                                self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                                let _ = self.consume(&TokenKind::Comma);
                                continue;
                            }
                        };
                        named_payload.push(ast::Field {
                            name: field_name,
                            ty: field_ty,
                        });
                        let _ = self.consume(&TokenKind::Comma);
                    }
                    let _ = self.consume(&TokenKind::RBrace);
                }
                variants.push(ast::Variant {
                    name: variant_name,
                    payload,
                    named_payload,
                });
                let _ = self.consume(&TokenKind::Comma);
            }
            let _ = self.consume(&TokenKind::RBrace);
        }
        Some(ast::Item::Enum(ast::Enum {
            name,
            generics,
            variants,
            repr: self.pending_repr.take(),
            is_pub,
        }))
    }

    fn parse_trait(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwTrait);
        let name = self.expect_ident("expected trait name")?;
        let generics = self.parse_generic_params();
        if !self.consume(&TokenKind::LBrace) {
            self.push_diag_here("expected `{` after trait name");
            return None;
        }
        let mut associated_types = Vec::new();
        let mut associated_consts = Vec::new();
        let mut methods = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            if self.at(&TokenKind::KwConst) {
                let _ = self.consume(&TokenKind::KwConst);
                let Some(name) = self.expect_ident("expected associated const name") else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in associated const declaration");
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                }
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                associated_consts.push(ast::TraitConst { name, ty });
                let _ = self.consume(&TokenKind::Semi);
                continue;
            }
            if self.at(&TokenKind::KwType) {
                let _ = self.advance();
                let Some(name) = self.expect_ident("expected associated type name") else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                associated_types.push(name);
                let _ = self.consume(&TokenKind::Semi);
                continue;
            }
            if !self.consume(&TokenKind::KwFn) {
                self.push_diag_here("expected `fn` in trait body");
                self.recover_item();
                continue;
            }
            let method_name = self.expect_ident("expected trait method name")?;
            let _method_generics = self.parse_generic_params();
            if !self.consume(&TokenKind::LParen) {
                self.push_diag_here("expected `(` after trait method name");
                return None;
            }
            let mut params = Vec::new();
            while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                let param_name = match self.expect_ident("expected parameter name") {
                    Some(v) => v,
                    None => break,
                };
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in parameter declaration");
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                }
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                };
                params.push(ast::Param {
                    name: param_name,
                    ty,
                });
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::RParen);
            let return_type = if self.consume(&TokenKind::Arrow) {
                self.parse_type().unwrap_or(Type::Void)
            } else {
                Type::Void
            };
            if self.at(&TokenKind::LBrace) {
                self.push_diag_here(
                    "trait default method bodies are not supported in v1; declare signatures only",
                );
                let _ = self.parse_block();
            } else {
                let _ = self.consume(&TokenKind::Semi);
            }
            methods.push(ast::TraitMethod {
                name: method_name,
                params,
                return_type,
            });
        }
        let _ = self.consume(&TokenKind::RBrace);
        Some(ast::Item::Trait(ast::Trait {
            name,
            generics,
            associated_types,
            associated_consts,
            methods,
            is_pub,
        }))
    }

    fn parse_impl(&mut self, is_pub: bool) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwImpl);
        let generics = self.parse_generic_params();
        let first = self.parse_type()?;
        let (trait_name, for_type) = if self.consume(&TokenKind::KwFor) {
            let Some(ty) = self.parse_type() else {
                self.push_diag_here("expected type after `for`");
                return None;
            };
            let trait_name = match first {
                Type::Named { name, args } if args.is_empty() => Some(name),
                Type::TypeVar(name) => Some(name),
                _ => {
                    self.push_diag_here("trait in impl must be a named trait");
                    None
                }
            };
            (trait_name, ty)
        } else {
            (None, first)
        };
        if !self.consume(&TokenKind::LBrace) {
            self.push_diag_here("expected `{` after impl header");
            return None;
        }
        let mut associated_types = Vec::new();
        let mut associated_consts = Vec::new();
        let mut methods = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            if self.at(&TokenKind::KwType) {
                let _ = self.consume(&TokenKind::KwType);
                let Some(name) = self.expect_ident("expected associated type name") else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                if !self.consume(&TokenKind::Eq) {
                    self.push_diag_here("expected `=` in associated type impl");
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                }
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                associated_types.push((name, ty));
                let _ = self.consume(&TokenKind::Semi);
                continue;
            }
            if self.at(&TokenKind::KwConst) {
                let _ = self.consume(&TokenKind::KwConst);
                let Some(name) = self.expect_ident("expected associated const name") else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in associated const impl");
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                }
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                if !self.consume(&TokenKind::Eq) {
                    self.push_diag_here("expected `=` in associated const impl");
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                }
                let Some(value) = self.parse_expr(0) else {
                    self.consume_until(&[TokenKind::Semi, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Semi);
                    continue;
                };
                associated_consts.push(ast::ConstItem {
                    name,
                    ty,
                    value,
                    is_pub: false,
                });
                let _ = self.consume(&TokenKind::Semi);
                continue;
            }
            match self.parse_function() {
                Some(ast::Item::Function(function)) => methods.push(function),
                Some(_) => {
                    self.push_diag_here("expected function in impl body");
                    self.recover_item();
                }
                None => {
                    self.recover_item();
                }
            }
        }
        let _ = self.consume(&TokenKind::RBrace);
        Some(ast::Item::Impl(ast::Impl {
            trait_name,
            generics,
            for_type,
            associated_types,
            associated_consts,
            methods,
            is_pub,
        }))
    }

    fn parse_function(&mut self) -> Option<ast::Item> {
        let mut is_pubext = false;
        let mut is_async = false;
        let mut is_pub = false;
        let mut is_extern = false;
        let mut is_unsafe = false;
        let mut execution_space = ast::ExecutionSpace::Host;
        let mut saw_execution_space = false;

        loop {
            let consumed = match self.peek_kind() {
                TokenKind::KwPubext if !is_pubext && !is_pub && !is_extern => {
                    is_pubext = true;
                    is_pub = true;
                    is_extern = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwAsync if !is_async => {
                    is_async = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwPub if !is_pub && !is_pubext => {
                    is_pub = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwExt if !is_extern && !is_pubext => {
                    is_extern = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwUnsafe if !is_unsafe => {
                    is_unsafe = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwHost if !saw_execution_space => {
                    execution_space = ast::ExecutionSpace::Host;
                    saw_execution_space = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwPure if !saw_execution_space => {
                    execution_space = ast::ExecutionSpace::Pure;
                    saw_execution_space = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwDevice if !saw_execution_space => {
                    execution_space = ast::ExecutionSpace::Device;
                    saw_execution_space = true;
                    let _ = self.advance();
                    true
                }
                TokenKind::KwKernel if !saw_execution_space => {
                    execution_space = ast::ExecutionSpace::Kernel;
                    saw_execution_space = true;
                    let _ = self.advance();
                    true
                }
                _ => false,
            };
            if !consumed {
                break;
            }
        }
        if is_unsafe && self.at(&TokenKind::LParen) {
            self.push_diag_here(
                "inline unsafe metadata is removed; use `unsafe fn ...` and compiler-generated unsafe contracts/docs",
            );
            return None;
        }
        if is_pub && is_extern && !is_pubext {
            self.push_diag_here("use `pubext c fn` for exported C symbols");
            return None;
        }
        let abi = if is_pubext || is_extern {
            let raw_abi = self.expect_ident("expected ABI identifier (for example: `c`)")?;
            if !raw_abi.eq_ignore_ascii_case("c") {
                self.push_diag_here("unsupported ABI; only `c` is supported");
                return None;
            }
            Some("c".to_string())
        } else {
            None
        };
        if !self.consume(&TokenKind::KwFn) {
            if is_pub || is_extern || is_pubext {
                self.push_diag_here("expected `fn` declaration");
            }
            return None;
        }
        let name = self.expect_ident("expected function name")?;
        let link_name = is_extern.then(|| name.clone());
        let generics = self.parse_generic_params();

        if !self.consume(&TokenKind::LParen) {
            self.push_diag_here("expected `(` after function name");
            return None;
        }
        let mut params = Vec::new();
        while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
            let param_name = match self.expect_ident("expected parameter name") {
                Some(v) => v,
                None => break,
            };
            if !self.consume(&TokenKind::Colon) {
                self.push_diag_here("expected `:` in parameter declaration");
                self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                let _ = self.consume(&TokenKind::Comma);
                continue;
            }
            let Some(ty) = self.parse_type() else {
                self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                let _ = self.consume(&TokenKind::Comma);
                continue;
            };
            params.push(ast::Param {
                name: param_name,
                ty,
            });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        let _ = self.consume(&TokenKind::RParen);

        let return_type = if self.consume(&TokenKind::Arrow) {
            self.parse_type().unwrap_or(Type::Void)
        } else {
            Type::Void
        };

        let mut body = Vec::new();
        if self.consume(&TokenKind::Semi) {
            // ext declaration
        } else if self.consume(&TokenKind::LBrace) {
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                match self.parse_stmt() {
                    Some(stmt) => body.push(stmt),
                    None => self.recover_stmt(),
                }
            }
            let _ = self.consume(&TokenKind::RBrace);
        } else {
            self.push_diag_here("expected function body `{ ... }` or `;`");
        }

        Some(ast::Item::Function(ast::Function {
            name,
            link_name,
            generics,
            params,
            return_type,
            body,
            is_unsafe,
            unsafe_meta: None,
            is_async,
            is_pub,
            is_pubext,
            is_extern,
            execution_space,
            abi,
            ffi_panic: self.pending_ffi_panic.take(),
        }))
    }

    fn parse_stmt(&mut self) -> Option<Stmt> {
        if self.consume(&TokenKind::KwLet) {
            let mutable = self.consume_ident("mut");
            let pattern = self.parse_pattern()?;
            if matches!(pattern, Pattern::Wildcard) {
                self.push_diag_here("`let _ = ...` is removed; use `discard <expr>`");
                return None;
            }
            let ty = if self.consume(&TokenKind::Colon) {
                self.parse_type()
            } else {
                None
            };
            if !self.consume(&TokenKind::Eq) {
                self.push_diag_here("expected `=` in let binding");
                return None;
            }
            let value = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(match pattern {
                Pattern::Ident(name) => Stmt::Let {
                    name,
                    mutable,
                    ty,
                    value,
                },
                pattern => Stmt::LetPattern {
                    pattern,
                    mutable,
                    ty,
                    value,
                },
            });
        }

        if self.consume(&TokenKind::KwIf) {
            let condition = self.parse_expr(0)?;
            let then_body = self.parse_if_branch_body()?;
            let else_body = if self.consume(&TokenKind::KwElse) {
                if self.at(&TokenKind::KwIf) {
                    vec![self.parse_stmt()?]
                } else {
                    self.parse_if_branch_body()?
                }
            } else {
                Vec::new()
            };
            return Some(Stmt::If {
                condition,
                then_body,
                else_body,
            });
        }

        if self.consume(&TokenKind::KwWhile) {
            let condition = self.parse_expr(0)?;
            let body = self.parse_block()?;
            return Some(Stmt::While { condition, body });
        }

        if self.consume(&TokenKind::KwFor) {
            return self.parse_for_stmt();
        }

        if self.consume(&TokenKind::KwLoop) {
            let body = self.parse_block()?;
            return Some(Stmt::Loop { body });
        }

        if self.consume(&TokenKind::KwBreak) {
            let value = if self.expr_starts_here() {
                Some(self.parse_expr(0)?)
            } else {
                None
            };
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Break(value));
        }

        if self.consume(&TokenKind::KwContinue) {
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Continue);
        }

        if self.consume(&TokenKind::KwRequires) {
            let expr = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Requires(expr));
        }

        if self.consume(&TokenKind::KwEnsures) {
            let expr = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Ensures(expr));
        }

        if self.consume(&TokenKind::KwReturn) {
            let expr = if self.at(&TokenKind::Semi) {
                None
            } else {
                Some(self.parse_expr(0)?)
            };
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Return(expr));
        }

        if self.consume(&TokenKind::KwDefer) {
            let expr = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Defer(expr));
        }

        if self.consume(&TokenKind::KwDiscard) {
            let expr = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Expr(expr));
        }

        if self.consume(&TokenKind::KwMatch) {
            let scrutinee = self.parse_expr(0)?;
            let arms = self.parse_match_arms()?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Match { scrutinee, arms });
        }

        let expr = self.parse_expr(0)?;
        if self.consume(&TokenKind::Eq) {
            let value = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(match expr {
                Expr::Ident(target) => Stmt::Assign { target, value },
                Expr::Index { base, index } => Stmt::Expr(Expr::Call {
                    callee: "__index_assign".to_string(),
                    args: vec![*base, *index, value],
                }),
                _ => {
                    self.push_diag_here("expected assignment target");
                    Stmt::Expr(value)
                }
            });
        }
        if let Some(op) = self.compound_assign_op() {
            let _ = self.advance();
            let value = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(match expr {
                Expr::Ident(target) => Stmt::CompoundAssign { target, op, value },
                _ => {
                    self.push_diag_here("expected assignment target");
                    Stmt::Expr(value)
                }
            });
        }
        let _ = self.consume(&TokenKind::Semi);
        Some(Stmt::Expr(expr))
    }

    fn parse_block(&mut self) -> Option<Vec<Stmt>> {
        if !self.consume(&TokenKind::LBrace) {
            self.push_diag_here("expected `{` to start block");
            return None;
        }
        let mut body = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            if let Some(stmt) = self.parse_stmt() {
                body.push(stmt);
            } else {
                self.recover_stmt();
            }
        }
        let _ = self.consume(&TokenKind::RBrace);
        Some(body)
    }

    fn parse_if_branch_body(&mut self) -> Option<Vec<Stmt>> {
        if self.consume(&TokenKind::KwThen) {
            return self.parse_then_control_stmt().map(|stmt| vec![stmt]);
        }
        self.parse_block()
    }

    fn parse_if_expr_branch(&mut self) -> Option<Expr> {
        if self.consume(&TokenKind::KwThen) {
            return self.parse_expr(0);
        }
        if self.consume(&TokenKind::LBrace) {
            let expr = self.parse_expr(0)?;
            if !self.consume(&TokenKind::RBrace) {
                self.push_diag_here("expected `}` to close if-expression branch");
                return None;
            }
            return Some(expr);
        }
        self.push_diag_here("if expression requires `then <expr>` or `{ <expr> }` branch");
        None
    }

    fn parse_then_control_stmt(&mut self) -> Option<Stmt> {
        if self.consume(&TokenKind::KwReturn) {
            let expr = if self.expr_starts_here() {
                Some(self.parse_expr(0)?)
            } else {
                None
            };
            return Some(Stmt::Return(expr));
        }
        if self.consume(&TokenKind::KwBreak) {
            let value = if self.expr_starts_here() {
                Some(self.parse_expr(0)?)
            } else {
                None
            };
            return Some(Stmt::Break(value));
        }
        if self.consume(&TokenKind::KwContinue) {
            return Some(Stmt::Continue);
        }
        self.push_diag_here("`if ... then ...` requires `return`, `break`, or `continue`");
        None
    }

    fn parse_for_stmt(&mut self) -> Option<Stmt> {
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_)))
            && self.peek_n(1).is_some_and(|t| t.kind == TokenKind::KwIn)
        {
            let binding = self.expect_ident("expected loop binding name after `for`")?;
            let _ = self.consume(&TokenKind::KwIn);
            let iterable = self.parse_expr(0)?;
            let body = self.parse_block()?;
            return Some(Stmt::ForIn {
                binding,
                iterable,
                body,
            });
        }

        let init = if self.consume(&TokenKind::Semi) {
            None
        } else {
            Some(Box::new(self.parse_for_clause_stmt(true)?))
        };
        let condition = if self.consume(&TokenKind::Semi) {
            None
        } else {
            let condition = self.parse_expr(0)?;
            if !self.consume(&TokenKind::Semi) {
                self.push_diag_here("expected `;` after for-loop condition");
                return None;
            }
            Some(condition)
        };
        let step = if self.at(&TokenKind::LBrace) {
            None
        } else {
            Some(Box::new(self.parse_for_clause_stmt(false)?))
        };
        let body = self.parse_block()?;
        Some(Stmt::For {
            init,
            condition,
            step,
            body,
        })
    }

    fn parse_for_clause_stmt(&mut self, expect_trailing_semi: bool) -> Option<Stmt> {
        let stmt = if self.consume(&TokenKind::KwLet) {
            let mutable = self.consume_ident("mut");
            let pattern = self.parse_pattern()?;
            if matches!(pattern, Pattern::Wildcard) {
                self.push_diag_here("`let _ = ...` is removed; use `discard <expr>`");
                return None;
            }
            let ty = if self.consume(&TokenKind::Colon) {
                self.parse_type()
            } else {
                None
            };
            if !self.consume(&TokenKind::Eq) {
                self.push_diag_here("expected `=` in let binding");
                return None;
            }
            let value = self.parse_expr(0)?;
            match pattern {
                Pattern::Ident(name) => Stmt::Let {
                    name,
                    mutable,
                    ty,
                    value,
                },
                pattern => Stmt::LetPattern {
                    pattern,
                    mutable,
                    ty,
                    value,
                },
            }
        } else if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_)))
            && self.peek_n(1).is_some_and(|t| t.kind == TokenKind::Eq)
        {
            let target = self.expect_ident("expected assignment target")?;
            let _ = self.consume(&TokenKind::Eq);
            let value = self.parse_expr(0)?;
            Stmt::Assign { target, value }
        } else if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_)))
            && self.compound_assign_op().is_some()
        {
            let op = self.compound_assign_op()?;
            let target = self.expect_ident("expected assignment target")?;
            let _ = self.advance();
            let value = self.parse_expr(0)?;
            Stmt::CompoundAssign { target, op, value }
        } else {
            let value = self.parse_expr(0)?;
            Stmt::Expr(value)
        };

        if expect_trailing_semi && !self.consume(&TokenKind::Semi) {
            self.push_diag_here("expected `;` in for-loop header");
            return None;
        }
        Some(stmt)
    }

    fn parse_pattern(&mut self) -> Option<Pattern> {
        let mut patterns = Vec::new();
        patterns.push(self.parse_single_pattern()?);
        while self.consume(&TokenKind::Pipe) {
            patterns.push(self.parse_single_pattern()?);
        }
        if patterns.len() == 1 {
            patterns.pop()
        } else {
            Some(Pattern::Or(patterns))
        }
    }

    fn parse_single_pattern(&mut self) -> Option<Pattern> {
        let token = self.peek()?.clone();
        if token.kind == TokenKind::LParen {
            let _ = self.advance();
            if self.consume(&TokenKind::RParen) {
                return Some(Pattern::Tuple(Vec::new()));
            }
            let first = self.parse_pattern()?;
            if !self.consume(&TokenKind::Comma) {
                if !self.consume(&TokenKind::RParen) {
                    self.push_diag_here("expected `)` to close grouped pattern");
                    return None;
                }
                return Some(first);
            }
            let mut items = vec![first];
            while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                items.push(self.parse_pattern()?);
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            if !self.consume(&TokenKind::RParen) {
                self.push_diag_here("expected `)` to close tuple pattern");
                return None;
            }
            return Some(Pattern::Tuple(items));
        }
        if let TokenKind::Ident(struct_name) = token.kind.clone() {
            if self
                .peek_n(1)
                .is_some_and(|tok| tok.kind == TokenKind::LBrace)
            {
                let _ = self.advance();
                let _ = self.consume(&TokenKind::LBrace);
                let mut fields = Vec::new();
                while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                    let field_name = self.expect_ident("expected field name in struct pattern")?;
                    let binding = if self.consume(&TokenKind::Colon) {
                        self.expect_ident("expected binding name in struct pattern field")?
                    } else {
                        field_name.clone()
                    };
                    fields.push((field_name, binding));
                    if !self.consume(&TokenKind::Comma) {
                        break;
                    }
                }
                if !self.consume(&TokenKind::RBrace) {
                    self.push_diag_here("expected `}` to close struct pattern");
                    return None;
                }
                return Some(Pattern::Struct {
                    name: struct_name.to_string(),
                    fields,
                });
            }
        }
        let expr = self.parse_prefix_expr()?;
        match expr {
            Expr::Int(v) => Some(Pattern::Int(v)),
            Expr::Bool(v) => Some(Pattern::Bool(v)),
            Expr::Ident(name) if name == "_" => Some(Pattern::Wildcard),
            Expr::Ident(name) => {
                if name.chars().next().is_some_and(char::is_uppercase) {
                    self.push_diag_at(
                        token.line,
                        token.col,
                        "capitalized bare pattern is not supported; use `Enum::Variant` or a lowercase binding",
                    );
                    return None;
                }
                Some(Pattern::Ident(name))
            }
            Expr::Tuple(items) => {
                let mut patterns = Vec::with_capacity(items.len());
                for item in items {
                    let pattern = match item {
                        Expr::Int(v) => Pattern::Int(v),
                        Expr::Bool(v) => Pattern::Bool(v),
                        Expr::Ident(name) if name == "_" => Pattern::Wildcard,
                        Expr::Ident(name) => Pattern::Ident(name),
                        _ => {
                            self.push_diag_at(
                                token.line,
                                token.col,
                                "tuple pattern elements must be literals, identifiers, or nested tuple patterns",
                            );
                            return None;
                        }
                    };
                    patterns.push(pattern);
                }
                Some(Pattern::Tuple(patterns))
            }
            Expr::EnumInit {
                enum_name,
                variant,
                payload,
                named_payload,
            } => {
                let mut bindings = Vec::with_capacity(payload.len());
                let mut named_bindings = Vec::with_capacity(named_payload.len());
                for value in payload {
                    let Expr::Ident(name) = value else {
                        self.push_diag_at(
                            token.line,
                            token.col,
                            "enum variant pattern bindings must be identifiers",
                        );
                        return None;
                    };
                    bindings.push(name);
                }
                for (field, value) in named_payload {
                    let Expr::Ident(name) = value else {
                        self.push_diag_at(
                            token.line,
                            token.col,
                            "enum struct-variant pattern bindings must be identifiers",
                        );
                        return None;
                    };
                    named_bindings.push((field, name));
                }
                Some(Pattern::Variant {
                    enum_name,
                    variant,
                    bindings,
                    named_bindings,
                })
            }
            Expr::Call { callee, .. } => {
                let _ = callee;
                self.push_diag_at(
                    token.line,
                    token.col,
                    "unqualified enum variant pattern is not supported; use `Enum::Variant(...)`",
                );
                None
            }
            _ => {
                self.push_diag_at(token.line, token.col, "invalid match pattern");
                None
            }
        }
    }

    fn parse_expr(&mut self, min_prec: u8) -> Option<Expr> {
        let mut left = self.parse_prefix_expr()?;
        loop {
            if min_prec == 0 {
                if self.consume(&TokenKind::DotDot) {
                    let right = self.parse_expr(1)?;
                    left = Expr::Range {
                        start: Box::new(left),
                        end: Box::new(right),
                        inclusive: false,
                    };
                    continue;
                }
                if self.consume(&TokenKind::DotDotEq) {
                    self.push_diag_here("`..=` is removed; use `range.closed(start, end)`");
                    return None;
                }
            }
            let Some((op, prec)) = self.current_binary_op() else {
                break;
            };
            if prec < min_prec {
                break;
            }
            let _ = self.advance();
            let right = self.parse_expr(prec + 1)?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_prefix_expr(&mut self) -> Option<Expr> {
        if self.at(&TokenKind::Pipe) {
            return self.parse_lambda_expr();
        }
        if self.consume(&TokenKind::KwReturn) {
            let value = if self.expr_starts_here() {
                Some(Box::new(self.parse_expr(0)?))
            } else {
                None
            };
            return Some(Expr::Return(value));
        }
        if self.consume(&TokenKind::KwBreak) {
            let value = if self.expr_starts_here() {
                Some(Box::new(self.parse_expr(0)?))
            } else {
                None
            };
            return Some(Expr::Break(value));
        }
        if self.consume(&TokenKind::KwContinue) {
            return Some(Expr::Continue);
        }
        if self.consume(&TokenKind::KwLoop) {
            let body = self.parse_block()?;
            return Some(Expr::Loop { body });
        }
        if self.consume(&TokenKind::KwWhile) {
            let condition = self.parse_expr(0)?;
            let body = self.parse_block()?;
            return Some(Expr::While {
                condition: Box::new(condition),
                body,
            });
        }
        if self.consume(&TokenKind::KwFor) {
            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_)))
                && self.peek_n(1).is_some_and(|t| t.kind == TokenKind::KwIn)
            {
                let binding = self.expect_ident("expected loop binding name after `for`")?;
                let _ = self.consume(&TokenKind::KwIn);
                let iterable = self.parse_expr(0)?;
                let body = self.parse_block()?;
                return Some(Expr::ForIn {
                    binding,
                    iterable: Box::new(iterable),
                    body,
                });
            }
            let init = if self.consume(&TokenKind::Semi) {
                None
            } else {
                Some(Box::new(self.parse_for_clause_stmt(true)?))
            };
            let condition = if self.consume(&TokenKind::Semi) {
                None
            } else {
                let condition = self.parse_expr(0)?;
                if !self.consume(&TokenKind::Semi) {
                    self.push_diag_here("expected `;` after for-loop condition");
                    return None;
                }
                Some(Box::new(condition))
            };
            let step = if self.at(&TokenKind::LBrace) {
                None
            } else {
                Some(Box::new(self.parse_for_clause_stmt(false)?))
            };
            let body = self.parse_block()?;
            return Some(Expr::For {
                init,
                condition,
                step,
                body,
            });
        }
        if self.consume(&TokenKind::KwMatch) {
            let scrutinee = self.parse_expr(0)?;
            let arms = self.parse_match_arms()?;
            return Some(Expr::Match {
                scrutinee: Box::new(scrutinee),
                arms,
            });
        }
        if self.consume(&TokenKind::KwIf) {
            let condition = self.parse_expr(0)?;
            let then_expr = self.parse_if_expr_branch()?;
            if !self.consume(&TokenKind::KwElse) {
                self.push_diag_here("if expression requires `else` branch");
                return None;
            }
            let else_expr = if self.at(&TokenKind::KwIf) {
                self.parse_prefix_expr()?
            } else {
                self.parse_if_expr_branch()?
            };
            return Some(Expr::If {
                condition: Box::new(condition),
                then_expr: Box::new(then_expr),
                else_expr: Box::new(else_expr),
            });
        }
        if self.consume(&TokenKind::KwTry) {
            let try_expr = self.parse_expr(0)?;
            if !self.consume(&TokenKind::KwCatch) {
                self.push_diag_here("expected `catch` in try/catch expression");
                return None;
            }
            let catch_expr = self.parse_expr(0)?;
            return Some(Expr::TryCatch {
                try_expr: Box::new(try_expr),
                catch_expr: Box::new(catch_expr),
            });
        }
        if self.consume(&TokenKind::KwAwait) {
            let awaited = self.parse_prefix_expr()?;
            return Some(Expr::Await(Box::new(awaited)));
        }
        if self.consume(&TokenKind::KwDiscard) {
            let value = self.parse_expr(0)?;
            return Some(Expr::Discard(Box::new(value)));
        }
        if self.consume(&TokenKind::KwUnsafe) {
            if self.at(&TokenKind::LParen) {
                self.push_diag_here(
                    "inline unsafe metadata is removed; use `unsafe { ... }` and compiler-generated unsafe contracts/docs",
                );
                return None;
            }
            if !self.consume(&TokenKind::LBrace) {
                self.push_diag_here("expected `{` after `unsafe`");
                return None;
            }
            let mut body = Vec::new();
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                match self.parse_stmt() {
                    Some(stmt) => body.push(stmt),
                    None => self.recover_stmt(),
                }
            }
            let _ = self.consume(&TokenKind::RBrace);
            return Some(Expr::UnsafeBlock { body, meta: None });
        }
        if self.consume(&TokenKind::Bang) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(expr),
            });
        }
        if self.consume(&TokenKind::Minus) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::Neg,
                expr: Box::new(expr),
            });
        }
        if self.consume(&TokenKind::Plus) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::Plus,
                expr: Box::new(expr),
            });
        }
        if self.consume(&TokenKind::Tilde) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::BitNot,
                expr: Box::new(expr),
            });
        }
        if self.consume(&TokenKind::Hash) {
            if !self.consume(&TokenKind::LBrace) {
                self.push_diag_here("expected `{` after `#` for object literal");
                return None;
            }
            let mut fields = Vec::new();
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                let Some(key_token) = self.advance() else {
                    break;
                };
                let key = match key_token.kind {
                    TokenKind::Str(value) => value,
                    TokenKind::Ident(_value) => {
                        self.push_diag_at(
                            key_token.line,
                            key_token.col,
                            "object literal keys must be quoted strings",
                        );
                        return None;
                    }
                    _ => {
                        self.push_diag_at(
                            key_token.line,
                            key_token.col,
                            "object literal key must be a quoted string",
                        );
                        return None;
                    }
                };
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in object literal");
                    return None;
                }
                let value = self.parse_expr(0)?;
                fields.push((key, value));
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::RBrace);
            return Some(Expr::ObjectLiteral(
                fields
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value))
                    .collect(),
            ));
        }

        let token = self.advance()?;
        let mut expr = match token.kind {
            TokenKind::Int(v) => Expr::Int(v),
            TokenKind::Float { value, bits } => Expr::Float { value, bits },
            TokenKind::Char(value) => Expr::Char(value),
            TokenKind::KwTrue => Expr::Bool(true),
            TokenKind::KwFalse => Expr::Bool(false),
            TokenKind::Str(v) => Expr::Str(v.to_string()),
            TokenKind::KwRpc => Expr::Ident("rpc".to_string()),
            TokenKind::Ident(name) => {
                if self.looks_like_struct_initializer() {
                    let _ = self.consume(&TokenKind::LBrace);
                    let mut fields = Vec::new();
                    while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                        let field_name =
                            self.expect_ident("expected field name in struct initializer")?;
                        if !self.consume(&TokenKind::Colon) {
                            self.push_diag_here("expected `:` in struct initializer");
                            return None;
                        }
                        let value = self.parse_expr(0)?;
                        fields.push((field_name, value));
                        if !self.consume(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let _ = self.consume(&TokenKind::RBrace);
                    Expr::StructInit {
                        name: name.to_string(),
                        fields,
                    }
                } else {
                    Expr::Ident(name.to_string())
                }
            }
            TokenKind::LParen => {
                if self.consume(&TokenKind::RParen) {
                    Expr::Tuple(Vec::new())
                } else {
                    let first = self.parse_expr(0)?;
                    if !self.consume(&TokenKind::Comma) {
                        let _ = self.consume(&TokenKind::RParen);
                        Expr::Group(Box::new(first))
                    } else {
                        let mut items = vec![first];
                        while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                            items.push(self.parse_expr(0)?);
                            if !self.consume(&TokenKind::Comma) {
                                break;
                            }
                        }
                        let _ = self.consume(&TokenKind::RParen);
                        Expr::Tuple(items)
                    }
                }
            }
            TokenKind::LBracket => {
                let mut items = Vec::new();
                while !self.at(&TokenKind::RBracket) && !self.at(&TokenKind::Eof) {
                    items.push(self.parse_expr(0)?);
                    if !self.consume(&TokenKind::Comma) {
                        break;
                    }
                }
                let _ = self.consume(&TokenKind::RBracket);
                Expr::ArrayLiteral(items)
            }
            _ => {
                self.push_diag_at(token.line, token.col, "unexpected token in expression");
                return None;
            }
        };

        loop {
            if self.consume(&TokenKind::Dot) {
                let seg = self.expect_member_name("expected member name after `.`")?;
                expr = Expr::FieldAccess {
                    base: Box::new(expr),
                    field: seg,
                };
                continue;
            }
            if self.at_double_colon() {
                let Some(enum_name) = Self::expr_to_callee_name(&expr) else {
                    self.push_diag_here("expected enum path before `::`");
                    return None;
                };
                expr = self.parse_enum_value_expr(enum_name)?;
                continue;
            }
            if self.at(&TokenKind::Lt) {
                if let Some(generic_callee) = self.try_parse_generic_callee(&expr) {
                    expr = generic_callee;
                    continue;
                }
            }
            if self.consume(&TokenKind::LParen) {
                let mut args = Vec::new();
                while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                    if let Some(arg) = self.parse_expr(0) {
                        args.push(arg);
                    }
                    if !self.consume(&TokenKind::Comma) {
                        break;
                    }
                }
                let _ = self.consume(&TokenKind::RParen);
                let Some(callee) = Self::expr_to_callee_name(&expr) else {
                    self.push_diag_here("callee must be an identifier");
                    return None;
                };
                if callee == "unsafe_reason" {
                    self.push_diag_here(
                        "`unsafe_reason(...)` is removed; use `unsafe { ... }` and compiler-generated unsafe contracts/docs",
                    );
                    return None;
                }
                if callee == "unsafe" {
                    self.push_diag_here(
                        "`unsafe(...)` expression form is removed; use `unsafe { ... }`",
                    );
                    return None;
                } else if callee == "range.closed" {
                    if args.len() != 2 {
                        self.push_diag_here("`range.closed` requires exactly 2 arguments");
                        return None;
                    }
                    expr = Expr::Range {
                        start: Box::new(args[0].clone()),
                        end: Box::new(args[1].clone()),
                        inclusive: true,
                    };
                } else {
                    expr = Expr::Call { callee, args };
                }
                continue;
            }
            if self.consume(&TokenKind::LBracket) {
                let index = self.parse_expr(0)?;
                if !self.consume(&TokenKind::RBracket) {
                    self.push_diag_here("expected `]` after index expression");
                    return None;
                }
                expr = Expr::Index {
                    base: Box::new(expr),
                    index: Box::new(index),
                };
                continue;
            }
            break;
        }

        Some(expr)
    }

    fn parse_enum_value_expr(&mut self, enum_name: String) -> Option<Expr> {
        let _ = self.consume(&TokenKind::Colon);
        let _ = self.consume(&TokenKind::Colon);
        let variant = self.expect_ident("expected enum variant name")?;
        let mut payload = Vec::new();
        let mut named_payload = Vec::new();
        if self.consume(&TokenKind::LParen) {
            while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                payload.push(self.parse_expr(0)?);
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::RParen);
        } else if self.looks_like_enum_struct_variant_initializer() {
            let _ = self.consume(&TokenKind::LBrace);
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                let field_name =
                    self.expect_ident("expected field name in enum struct-variant initializer")?;
                let value = if self.consume(&TokenKind::Colon) {
                    self.parse_expr(0)?
                } else {
                    Expr::Ident(field_name.clone())
                };
                named_payload.push((field_name, value));
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::RBrace);
        }
        Some(Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        })
    }

    fn parse_match_arms(&mut self) -> Option<Vec<MatchArm>> {
        if !self.consume(&TokenKind::LBrace) {
            self.push_diag_here("expected `{` after match scrutinee");
            return None;
        }
        let mut arms = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            let pattern = self.parse_pattern()?;
            if !self.consume(&TokenKind::FatArrow) {
                let guard = if self.consume(&TokenKind::KwIf) {
                    self.parse_expr(0)
                } else {
                    None
                };
                if !self.consume(&TokenKind::FatArrow) {
                    self.push_diag_here("expected `=>` in match arm");
                    return None;
                }
                let returns = self.consume(&TokenKind::KwReturn);
                let value = self.parse_expr(0)?;
                arms.push(MatchArm {
                    pattern,
                    guard,
                    returns,
                    value,
                });
                let _ = self.consume(&TokenKind::Comma);
                continue;
            }
            let returns = self.consume(&TokenKind::KwReturn);
            let value = self.parse_expr(0)?;
            arms.push(MatchArm {
                pattern,
                guard: None,
                returns,
                value,
            });
            let _ = self.consume(&TokenKind::Comma);
        }
        let _ = self.consume(&TokenKind::RBrace);
        Some(arms)
    }

    fn expr_starts_here(&self) -> bool {
        !matches!(
            self.peek_kind(),
            &TokenKind::Semi
                | &TokenKind::KwElse
                | &TokenKind::RBrace
                | &TokenKind::RParen
                | &TokenKind::Comma
                | &TokenKind::Eof
        )
    }

    fn parse_lambda_expr(&mut self) -> Option<Expr> {
        if !self.consume(&TokenKind::Pipe) {
            return None;
        }
        let mut params = Vec::new();
        if !self.at(&TokenKind::Pipe) {
            loop {
                let name = self.expect_ident("expected lambda parameter name")?;
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in lambda parameter");
                    return None;
                }
                let ty = self.parse_type()?;
                params.push(ast::Param { name, ty });
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
        }
        if !self.consume(&TokenKind::Pipe) {
            self.push_diag_here("expected `|` to close lambda parameter list");
            return None;
        }
        let return_type = if self.consume(&TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };
        let body = self.parse_expr(0)?;
        Some(Expr::Closure {
            params,
            return_type,
            body: Box::new(body),
        })
    }

    fn parse_type(&mut self) -> Option<Type> {
        if self.consume(&TokenKind::KwFn) {
            if !self.consume(&TokenKind::LParen) {
                self.push_diag_here("expected `(` after `fn` in function type");
                return None;
            }
            let mut params = Vec::new();
            while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                let Some(param_ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                };
                params.push(param_ty);
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::RParen);
            let ret = if self.consume(&TokenKind::Arrow) {
                self.parse_type().unwrap_or(Type::Void)
            } else {
                Type::Void
            };
            return Some(Type::Function {
                params,
                ret: Box::new(ret),
            });
        }
        if self.consume_ident("dyn") {
            let trait_name = self.expect_ident("expected trait name after `dyn`")?;
            return Some(Type::DynTrait(trait_name));
        }
        if self.consume(&TokenKind::LParen) {
            if self.consume(&TokenKind::RParen) {
                return Some(Type::Tuple(Vec::new()));
            }
            let first = self.parse_type()?;
            if self.consume(&TokenKind::Comma) {
                let mut items = vec![first];
                while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                    let Some(item) = self.parse_type() else {
                        self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                        let _ = self.consume(&TokenKind::Comma);
                        continue;
                    };
                    items.push(item);
                    if !self.consume(&TokenKind::Comma) {
                        break;
                    }
                }
                let _ = self.consume(&TokenKind::RParen);
                return Some(Type::Tuple(items));
            }
            let _ = self.consume(&TokenKind::RParen);
            return Some(first);
        }
        if self.consume(&TokenKind::Star) {
            let mutable = self.consume_ident("mut");
            let inner = self.parse_type()?;
            return Some(Type::Ptr {
                mutable,
                to: Box::new(inner),
            });
        }
        if self.consume(&TokenKind::Amp) {
            let lifetime = if self.consume(&TokenKind::Apostrophe) {
                Some(self.expect_ident("expected lifetime name after `'`")?)
            } else {
                None
            };
            let mutable = self.consume_ident("mut");
            let inner = self.parse_type()?;
            return Some(Type::Ref {
                mutable,
                lifetime,
                to: Box::new(inner),
            });
        }
        if self.consume(&TokenKind::LBracket) {
            if self.consume(&TokenKind::RBracket) {
                let elem = self.parse_type()?;
                return Some(Type::Slice(Box::new(elem)));
            }
            let elem = self.parse_type()?;
            if !self.consume(&TokenKind::Semi) {
                self.push_diag_here("expected `;` in array type");
                return None;
            }
            let len = match self.advance()?.kind {
                TokenKind::Int(v) if v >= 0 => match usize::try_from(v) {
                    Ok(value) => value,
                    Err(_) => {
                        self.push_diag_here("array length exceeds target usize");
                        return None;
                    }
                },
                _ => {
                    self.push_diag_here("expected array length integer");
                    return None;
                }
            };
            let _ = self.consume(&TokenKind::RBracket);
            return Some(Type::Array {
                elem: Box::new(elem),
                len,
            });
        }

        let name = self.expect_ident("expected type")?;
        let mut path_segments = vec![name];
        let mut saw_dot_separator = false;
        let mut saw_double_colon_separator = false;
        loop {
            if self.consume(&TokenKind::Dot) {
                let Some(segment) = self.expect_ident("expected type segment after `.`") else {
                    return None;
                };
                saw_dot_separator = true;
                path_segments.push(segment);
                continue;
            }
            if self.at(&TokenKind::Colon)
                && self
                    .peek_n(1)
                    .is_some_and(|token| matches!(token.kind, TokenKind::Colon))
            {
                let _ = self.consume(&TokenKind::Colon);
                let _ = self.consume(&TokenKind::Colon);
                let Some(segment) = self.expect_ident("expected type segment after `::`") else {
                    return None;
                };
                saw_double_colon_separator = true;
                path_segments.push(segment);
                continue;
            }
            break;
        }
        let mut args = Vec::new();
        if self.consume(&TokenKind::Lt) {
            while !self.at(&TokenKind::Gt) && !self.at(&TokenKind::Eof) {
                if let Some(ty) = self.parse_type() {
                    args.push(ty);
                }
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::Gt);
        }
        let joined_name = if path_segments
            .first()
            .is_some_and(|segment| segment == "Self")
            && saw_double_colon_separator
            && !saw_dot_separator
        {
            path_segments.join("::")
        } else {
            path_segments.join(".")
        };
        let scalar_name = path_segments
            .first()
            .map(String::as_str)
            .unwrap_or(joined_name.as_str());

        let ty = match (scalar_name, args.as_slice()) {
            ("never", []) => Type::Never,
            ("void", []) => Type::Void,
            ("bool", []) => Type::Bool,
            ("char", []) => Type::Char,
            ("str", []) => Type::Str,
            ("bytes", []) => Type::Bytes,
            ("i8", []) => Type::Int {
                signed: true,
                bits: 8,
            },
            ("i16", []) => Type::Int {
                signed: true,
                bits: 16,
            },
            ("i32", []) => Type::Int {
                signed: true,
                bits: 32,
            },
            ("i64", []) => Type::Int {
                signed: true,
                bits: 64,
            },
            ("i128", []) => Type::Int {
                signed: true,
                bits: 128,
            },
            ("isize", []) => Type::ISize,
            ("u8", []) => Type::Int {
                signed: false,
                bits: 8,
            },
            ("u16", []) => Type::Int {
                signed: false,
                bits: 16,
            },
            ("u32", []) => Type::Int {
                signed: false,
                bits: 32,
            },
            ("u64", []) => Type::Int {
                signed: false,
                bits: 64,
            },
            ("u128", []) => Type::Int {
                signed: false,
                bits: 128,
            },
            ("usize", []) => Type::USize,
            ("BigInt", []) | ("bigint", []) => Type::BigInt,
            ("BigUint", []) | ("biguint", []) => Type::BigUint,
            ("f32", []) => Type::Float { bits: 32 },
            ("f64", []) => Type::Float { bits: 64 },
            ("Decimal128", []) | ("decimal128", []) => Type::Decimal128,
            ("Uuid", []) | ("uuid", []) => Type::Uuid,
            ("Map", [key, value]) => Type::Map {
                key: Box::new(key.clone()),
                value: Box::new(value.clone()),
            },
            ("Set", [inner]) => Type::Set(Box::new(inner.clone())),
            ("Deque", [inner]) => Type::Deque(Box::new(inner.clone())),
            ("Ring", [inner]) => Type::Ring(Box::new(inner.clone())),
            ("Vec", [inner]) => Type::Vec(Box::new(inner.clone())),
            ("Option", [inner]) => Type::Option(Box::new(inner.clone())),
            ("Result", [ok, err]) => Type::Result {
                ok: Box::new(ok.clone()),
                err: Box::new(err.clone()),
            },
            ("Future", [inner]) => Type::Future(Box::new(inner.clone())),
            ("Path", []) | ("path", []) => Type::Path,
            ("PathBuf", []) | ("pathbuf", []) => Type::PathBuf,
            ("Url", []) | ("url", []) => Type::Url,
            ("SocketAddr", []) | ("socket_addr", []) => Type::SocketAddr,
            ("Duration", []) | ("duration", []) => Type::Duration,
            ("Instant", []) | ("instant", []) => Type::Instant,
            ("Decimal", []) | ("decimal", []) => Type::Decimal,
            ("DateTimeTz", []) | ("datetime_tz", []) => Type::DateTimeTz,
            ("ExitStatus", []) | ("exit_status", []) => Type::ExitStatus,
            _ => {
                if path_segments.len() == 1 && args.is_empty() {
                    if let Some(simd_ty) = Type::parse_builtin_simd_alias(&joined_name) {
                        simd_ty
                    } else if joined_name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c == '_')
                    {
                        Type::TypeVar(joined_name)
                    } else {
                        Type::Named {
                            name: joined_name,
                            args,
                        }
                    }
                } else {
                    Type::Named {
                        name: joined_name,
                        args,
                    }
                }
            }
        };
        Some(ty)
    }

    fn parse_generic_params(&mut self) -> Vec<ast::GenericParam> {
        let mut out = Vec::new();
        if !self.consume(&TokenKind::Lt) {
            return out;
        }
        while !self.at(&TokenKind::Gt) && !self.at(&TokenKind::Eof) {
            let Some(name) = self.expect_ident("expected generic parameter name") else {
                break;
            };
            let mut bounds = Vec::new();
            if self.consume(&TokenKind::Colon) {
                loop {
                    let Some(bound) = self.expect_ident("expected trait bound") else {
                        break;
                    };
                    bounds.push(bound);
                    if !self.consume(&TokenKind::Plus) {
                        break;
                    }
                }
            }
            out.push(ast::GenericParam { name, bounds });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        let _ = self.consume(&TokenKind::Gt);
        out
    }

    fn looks_like_struct_initializer(&self) -> bool {
        if !self.at(&TokenKind::LBrace) {
            return false;
        }
        match (self.peek_n(1), self.peek_n(2), self.peek_n(3)) {
            (
                Some(Token {
                    kind: TokenKind::RBrace,
                    ..
                }),
                _,
                _,
            ) => true,
            (
                Some(Token {
                    kind: TokenKind::Ident(_),
                    ..
                }),
                Some(Token {
                    kind: TokenKind::Colon,
                    ..
                }),
                next,
            ) => !matches!(
                next,
                Some(Token {
                    kind: TokenKind::Colon,
                    ..
                })
            ),
            _ => false,
        }
    }

    fn looks_like_enum_struct_variant_initializer(&self) -> bool {
        if !self.at(&TokenKind::LBrace) {
            return false;
        }
        match (self.peek_n(1), self.peek_n(2), self.peek_n(3)) {
            (
                Some(Token {
                    kind: TokenKind::RBrace,
                    ..
                }),
                _,
                _,
            ) => true,
            (
                Some(Token {
                    kind: TokenKind::Ident(_),
                    ..
                }),
                Some(Token {
                    kind: TokenKind::Colon | TokenKind::Comma | TokenKind::RBrace,
                    ..
                }),
                next,
            ) => !matches!(
                next,
                Some(Token {
                    kind: TokenKind::Colon,
                    ..
                })
            ),
            _ => false,
        }
    }

    fn try_parse_generic_callee(&mut self, expr: &Expr) -> Option<Expr> {
        let save = self.pos;
        let diag_len = self.diagnostics.len();
        let mut args = Vec::new();
        let _ = self.consume(&TokenKind::Lt);
        while !self.at(&TokenKind::Gt) && !self.at(&TokenKind::Eof) {
            let Some(ty) = self.parse_type() else {
                self.pos = save;
                self.diagnostics.truncate(diag_len);
                return None;
            };
            args.push(ty);
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        if !self.consume(&TokenKind::Gt) || !self.at(&TokenKind::LParen) {
            self.pos = save;
            self.diagnostics.truncate(diag_len);
            return None;
        }
        let callee = match expr {
            Expr::Ident(name) => name.clone(),
            _ => {
                self.pos = save;
                self.diagnostics.truncate(diag_len);
                return None;
            }
        };
        let rendered = args
            .iter()
            .map(|ty| ty.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Some(Expr::Ident(format!("{callee}<{rendered}>")))
    }

    fn expr_to_callee_name(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Ident(name) => Some(name.clone()),
            Expr::Group(inner) => Self::expr_to_callee_name(inner),
            Expr::FieldAccess { base, field } => {
                let base = Self::expr_to_callee_name(base)?;
                Some(format!("{base}.{field}"))
            }
            _ => None,
        }
    }

    fn current_binary_op(&self) -> Option<(BinaryOp, u8)> {
        let kind = &self.peek()?.kind;
        let (op, prec) = match kind {
            TokenKind::PipePipe => (BinaryOp::Or, 1),
            TokenKind::AmpAmp => (BinaryOp::And, 2),
            TokenKind::Pipe => (BinaryOp::BitOr, 3),
            TokenKind::Caret => (BinaryOp::BitXor, 4),
            TokenKind::Amp => (BinaryOp::BitAnd, 5),
            TokenKind::EqEq => (BinaryOp::Eq, 6),
            TokenKind::Neq => (BinaryOp::Neq, 6),
            TokenKind::Lt => (BinaryOp::Lt, 7),
            TokenKind::Lte => (BinaryOp::Lte, 7),
            TokenKind::Gt => (BinaryOp::Gt, 7),
            TokenKind::Gte => (BinaryOp::Gte, 7),
            TokenKind::LtLt => (BinaryOp::Shl, 8),
            TokenKind::GtGt => (BinaryOp::Shr, 8),
            TokenKind::Plus => (BinaryOp::Add, 9),
            TokenKind::Minus => (BinaryOp::Sub, 9),
            TokenKind::Star => (BinaryOp::Mul, 10),
            TokenKind::Slash => (BinaryOp::Div, 10),
            TokenKind::Percent => (BinaryOp::Mod, 10),
            _ => return None,
        };
        Some((op, prec))
    }

    fn compound_assign_op(&self) -> Option<BinaryOp> {
        match self.peek().map(|token| &token.kind) {
            Some(TokenKind::PlusEq) => Some(BinaryOp::Add),
            Some(TokenKind::MinusEq) => Some(BinaryOp::Sub),
            Some(TokenKind::StarEq) => Some(BinaryOp::Mul),
            Some(TokenKind::SlashEq) => Some(BinaryOp::Div),
            Some(TokenKind::PercentEq) => Some(BinaryOp::Mod),
            Some(TokenKind::LtLtEq) => Some(BinaryOp::Shl),
            Some(TokenKind::GtGtEq) => Some(BinaryOp::Shr),
            Some(TokenKind::AmpEq) => Some(BinaryOp::BitAnd),
            Some(TokenKind::CaretEq) => Some(BinaryOp::BitXor),
            Some(TokenKind::PipeEq) => Some(BinaryOp::BitOr),
            _ => None,
        }
    }

    fn at(&self, kind: &TokenKind) -> bool {
        self.peek().is_some_and(|tok| tok.kind == *kind)
    }

    fn peek_kind(&self) -> &TokenKind {
        self.peek()
            .map(|token| &token.kind)
            .unwrap_or(&TokenKind::Eof)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_n(&self, n: usize) -> Option<&Token> {
        self.tokens.get(self.pos + n)
    }

    fn advance(&mut self) -> Option<Token> {
        let tok = self.tokens.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn consume(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_ident(&mut self, message: &str) -> Option<String> {
        let token = self.advance()?;
        match token.kind {
            TokenKind::Ident(value) => Some(value.to_string()),
            // `rpc` is a contextual keyword: declarations use keyword position, but
            // module names and paths may still legally use `rpc`.
            TokenKind::KwRpc => Some("rpc".to_string()),
            _ => {
                self.push_diag_at(token.line, token.col, message);
                None
            }
        }
    }

    fn expect_member_name(&mut self, message: &str) -> Option<String> {
        let token = self.advance()?;
        match token.kind {
            TokenKind::Ident(value) => Some(value.to_string()),
            TokenKind::KwFn => Some("fn".to_string()),
            TokenKind::KwPub => Some("pub".to_string()),
            TokenKind::KwPubext => Some("pubext".to_string()),
            TokenKind::KwConst => Some("const".to_string()),
            TokenKind::KwStatic => Some("static".to_string()),
            TokenKind::KwExt => Some("ext".to_string()),
            TokenKind::KwUnsafe => Some("unsafe".to_string()),
            TokenKind::KwAsync => Some("async".to_string()),
            TokenKind::KwHost => Some("host".to_string()),
            TokenKind::KwPure => Some("pure".to_string()),
            TokenKind::KwDevice => Some("device".to_string()),
            TokenKind::KwKernel => Some("kernel".to_string()),
            TokenKind::KwAwait => Some("await".to_string()),
            TokenKind::KwRpc => Some("rpc".to_string()),
            TokenKind::KwUse => Some("use".to_string()),
            TokenKind::KwCore => Some("core".to_string()),
            TokenKind::KwMod => Some("mod".to_string()),
            TokenKind::KwStruct => Some("struct".to_string()),
            TokenKind::KwEnum => Some("enum".to_string()),
            TokenKind::KwTrait => Some("trait".to_string()),
            TokenKind::KwImpl => Some("impl".to_string()),
            TokenKind::KwFor => Some("for".to_string()),
            TokenKind::KwIn => Some("in".to_string()),
            TokenKind::KwLoop => Some("loop".to_string()),
            TokenKind::KwBreak => Some("break".to_string()),
            TokenKind::KwContinue => Some("continue".to_string()),
            TokenKind::KwTest => Some("test".to_string()),
            TokenKind::KwNondet => Some("nondet".to_string()),
            TokenKind::KwLet => Some("let".to_string()),
            TokenKind::KwRequires => Some("requires".to_string()),
            TokenKind::KwEnsures => Some("ensures".to_string()),
            TokenKind::KwReturn => Some("return".to_string()),
            TokenKind::KwDefer => Some("defer".to_string()),
            TokenKind::KwMatch => Some("match".to_string()),
            TokenKind::KwIf => Some("if".to_string()),
            TokenKind::KwThen => Some("then".to_string()),
            TokenKind::KwElse => Some("else".to_string()),
            TokenKind::KwWhile => Some("while".to_string()),
            TokenKind::KwTry => Some("try".to_string()),
            TokenKind::KwCatch => Some("catch".to_string()),
            TokenKind::KwDiscard => Some("discard".to_string()),
            TokenKind::KwTrue => Some("true".to_string()),
            TokenKind::KwFalse => Some("false".to_string()),
            _ => {
                self.push_diag_at(token.line, token.col, message);
                None
            }
        }
    }

    fn push_diag_here(&mut self, message: &str) {
        let (line, col) = self
            .peek()
            .map(|t| (t.line, t.col))
            .unwrap_or((1usize, 1usize));
        self.push_diag_at(line, col, message);
    }

    fn push_diag_at(&mut self, line: usize, col: usize, message: &str) {
        self.diagnostics.push(
            Diagnostic::new(Severity::Error, message, parser_help(message))
                .with_catalog_key(parser_catalog_key(message))
                .with_span(line, col, line, col + 1),
        );
    }

    fn consume_until(&mut self, kinds: &[TokenKind]) {
        while !self.at(&TokenKind::Eof) {
            if kinds.iter().any(|kind| self.at(kind)) {
                break;
            }
            self.pos += 1;
        }
    }

    fn recover_item(&mut self) {
        self.consume_until(&[
            TokenKind::KwUse,
            TokenKind::KwMod,
            TokenKind::KwFn,
            TokenKind::KwPub,
            TokenKind::KwPubext,
            TokenKind::KwConst,
            TokenKind::KwStatic,
            TokenKind::KwExt,
            TokenKind::KwUnsafe,
            TokenKind::KwAsync,
            TokenKind::KwHost,
            TokenKind::KwPure,
            TokenKind::KwDevice,
            TokenKind::KwKernel,
            TokenKind::KwRpc,
            TokenKind::KwStruct,
            TokenKind::KwEnum,
            TokenKind::KwTrait,
            TokenKind::KwImpl,
            TokenKind::KwTest,
            TokenKind::Hash,
            TokenKind::Semi,
            TokenKind::Eof,
        ]);
        if self.consume(&TokenKind::Semi) {
            return;
        }
        if !self.at(&TokenKind::Eof) && self.pos < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn recover_stmt(&mut self) {
        self.consume_until(&[
            TokenKind::Semi,
            TokenKind::RBrace,
            TokenKind::KwLet,
            TokenKind::KwIf,
            TokenKind::KwWhile,
            TokenKind::KwFor,
            TokenKind::KwLoop,
            TokenKind::KwBreak,
            TokenKind::KwContinue,
            TokenKind::KwReturn,
            TokenKind::KwDiscard,
            TokenKind::KwMatch,
            TokenKind::Eof,
        ]);
        let _ = self.consume(&TokenKind::Semi);
    }
}

