use super::*;

pub fn parse_program(source_path: &Path) -> Result<ParsedProgram> {
    Ok((*parse_program_shared_with_root_source(source_path, None)?).clone())
}

pub(crate) fn parse_program_with_metadata(source_path: &Path) -> Result<(ParsedProgram, bool)> {
    let (parsed, cache_hit) = parse_program_shared_with_root_source_telemetry(source_path, None)?;
    Ok(((*parsed).clone(), cache_hit))
}

pub fn parse_program_with_root_source(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<ParsedProgram> {
    Ok((*parse_program_shared_with_root_source(source_path, root_source_override)?).clone())
}

pub(crate) fn parse_program_shared(source_path: &Path) -> Result<Arc<ParsedProgram>> {
    parse_program_shared_with_root_source(source_path, None)
}

pub(crate) fn parse_program_shared_with_root_source(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<Arc<ParsedProgram>> {
    Ok(parse_program_shared_with_root_source_telemetry(source_path, root_source_override)?.0)
}

pub(crate) fn parse_program_shared_with_root_source_telemetry(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<(Arc<ParsedProgram>, bool)> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let parse_context = parse_project_context_for_source(&canonical)?;
    if let Some(source_override) = root_source_override {
        return parse_program_uncached_with_root_source(
            &canonical,
            Some(source_override),
            parse_context.as_ref(),
        )
        .map(Arc::new)
        .map(|parsed| (parsed, false));
    }
    if let Some(cached) = cached_parsed_program(&canonical) {
        return Ok((cached, true));
    }
    let parsed = Arc::new(parse_program_uncached_with_root_source(
        &canonical,
        None,
        parse_context.as_ref(),
    )?);
    store_parsed_program_cache(&canonical, Arc::clone(&parsed));
    Ok((parsed, false))
}

pub fn lower_fir_cached(parsed: &ParsedProgram) -> (hir::TypedModule, fir::FirModule) {
    let lowered = lower_fir_cached_shared(parsed);
    ((*lowered.typed).clone(), (*lowered.fir).clone())
}

pub(crate) fn lower_fir_cached_with_metadata(
    parsed: &ParsedProgram,
) -> ((hir::TypedModule, fir::FirModule), bool) {
    let (lowered, cache_hit) = lower_fir_cached_shared_telemetry(parsed);
    (
        ((*lowered.typed).clone(), (*lowered.fir).clone()),
        cache_hit,
    )
}

pub(crate) fn lower_fir_cached_shared(parsed: &ParsedProgram) -> SharedLoweredProgram {
    lower_fir_cached_shared_telemetry(parsed).0
}

pub(crate) fn lower_fir_cached_shared_telemetry(
    parsed: &ParsedProgram,
) -> (SharedLoweredProgram, bool) {
    let module_hash = parsed.module_fingerprint.clone();
    let cache = LOWER_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(cached) = guard.get(&module_hash) {
            return (
                SharedLoweredProgram {
                    typed: Arc::clone(&cached.typed),
                    fir: Arc::clone(&cached.fir),
                },
                true,
            );
        }
    }
    let typed = Arc::new(hir::lower(&parsed.module));
    let fir_module = Arc::new(fir::build_owned((*typed).clone()));
    if let Ok(mut guard) = cache.write() {
        guard.insert(
            module_hash,
            LowerCacheEntry {
                typed: Arc::clone(&typed),
                fir: Arc::clone(&fir_module),
            },
        );
    }
    (
        SharedLoweredProgram {
            typed,
            fir: fir_module,
        },
        false,
    )
}

// Safety policy and artifact emission helpers live in `pipeline/policy_artifacts.rs`
// to keep this driver file focused on orchestration, analysis, and lowering.
