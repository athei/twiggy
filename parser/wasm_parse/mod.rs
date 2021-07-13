use super::Parse;
use std::collections::HashMap;
use twiggy_ir::{self as ir, Id};
use twiggy_traits as traits;
use wasmparser::{
    self, Chunk, TypeDef, Operator, Parser, Payload, SectionReader, SectionWithLimitedItems,
    Type,
};

#[derive(Default)]
pub struct SectionIndices {
    type_: Option<usize>,
    code: Option<usize>,
    functions: Vec<Id>,
    tables: Vec<Id>,
    memories: Vec<Id>,
    globals: Vec<Id>,
}

#[derive(Default)]
struct ParseResult<'a> {
    sections: Vec<IndexedSection<'a>>,
    code_section: Option<CodeSection<'a>>,
    function_section: Option<FuncSection<'a>>,
    sizes: HashMap<usize, u32>,
}

struct IndexedSection<'a>(usize, wasmparser::Payload<'a>);
struct FuncSection<'a>(usize, wasmparser::FunctionSectionReader<'a>);
struct CodeSection<'a>(usize, Vec<(u32, wasmparser::FunctionBody<'a>)>);
struct CustomSectionReader<'a>(&'a str, &'a [u8]);
struct WrappedDataCountSection(wasmparser::Range);
struct WrappedStartSection(wasmparser::Range);

pub fn parse_items(items: &mut ir::ItemsBuilder, data: &[u8]) -> Result<(), traits::Error> {
    let module = parse_module(data)?;

    let sections_cnt = module.sections.len()
        + if module.code_section.is_some() { 1 } else { 0 }
        + if module.function_section.is_some() {
            1
        } else {
            0
        };
    let id = Id::section(sections_cnt);
    items.add_root(ir::Item::new(
        id,
        "wasm magic bytes".to_string(),
        0,
        ir::Misc::new(),
    ));

    // Before we actually parse any items prepare to parse a few sections
    // below, namely the code section. When parsing the code section we want
    // to try to assign human-readable names so we need the name section, if
    // present. Additionally we need to look at the number of imported
    // functions to handle the wasm function index space correctly.
    let names = parse_names_section(&module.sections)?;
    let imported_functions = count_imported_functions(&module.sections)?;

    // Next, we parse the function and code sections together, so that we
    // can collapse corresponding entries from the code and function
    // sections into a single representative IR item.
    match (module.function_section, module.code_section) {
        (Some(function_section), Some(code_section)) => (function_section, code_section)
            .parse_items(items, (imported_functions, &names, &module.sizes))?,
        _ => Err(traits::Error::with_msg(
            "function or code section is missing",
        ))?,
    };

    for IndexedSection(idx, section) in module.sections.into_iter() {
        let start = items.size_added();
        let name = get_section_name(&section);
        use Payload::*;
        match section {
            CustomSection { name, data, .. } => CustomSectionReader(name, data)
                .parse_items(items, (idx, *module.sizes.get(&idx).unwrap()))?,
            TypeSection(mut reader) => reader.parse_items(items, idx)?,
            ImportSection(mut reader) => reader.parse_items(items, idx)?,
            TableSection(mut reader) => reader.parse_items(items, idx)?,
            MemorySection(mut reader) => reader.parse_items(items, idx)?,
            GlobalSection(mut reader) => reader.parse_items(items, idx)?,
            ExportSection(mut reader) => reader.parse_items(items, idx)?,
            StartSection { range, .. } => WrappedStartSection(range).parse_items(items, idx)?,
            ElementSection(mut section) => section.parse_items(items, idx)?,
            DataSection(mut reader) => reader.parse_items(items, idx)?,
            DataCountSection { range, .. } => {
                WrappedDataCountSection(range).parse_items(items, idx)?
            }
            CodeSectionStart { .. } | CodeSectionEntry(_) | FunctionSection(_) => {
                unreachable!("unexpected code or function section found")
            }
            _ => (),
        };
        let id = Id::section(idx);
        let added = items.size_added() - start;
        let size = module
            .sizes
            .get(&idx)
            .ok_or_else(|| traits::Error::with_msg("Could not find section size"))?;
        assert!(added <= *size);
        items.add_root(ir::Item::new(id, name, size - added, ir::Misc::new()));
    }

    Ok(())
}

pub fn parse_edges(items: &mut ir::ItemsBuilder, data: &[u8]) -> Result<(), traits::Error> {
    let module = parse_module(data)?;

    // Like above we do some preprocessing here before actually drawing all
    // the edges below. Here we primarily want to learn some properties of
    // the wasm module, such as what `Id` is mapped to all index spaces in
    // the wasm module. To handle that we build up all this data in
    // `SectionIndices` here as we parse all the various sections.
    let mut indices = SectionIndices::default();
    for IndexedSection(idx, section) in module.sections.iter() {
        use Payload::*;
        match section {
            TypeSection(_) => {
                indices.type_ = Some(*idx);
            }
            ImportSection(reader) => {
                for (i, import) in reader.clone().into_iter().enumerate() {
                    let id = Id::entry(*idx, i);
                    match import?.ty {
                        wasmparser::ImportSectionEntryType::Function(_) => {
                            indices.functions.push(id)
                        }
                        wasmparser::ImportSectionEntryType::Table(_) => indices.tables.push(id),
                        wasmparser::ImportSectionEntryType::Memory(_) => indices.memories.push(id),
                        wasmparser::ImportSectionEntryType::Global(_) => indices.globals.push(id),
                        _ => (),
                    }
                }
            }
            GlobalSection(reader) => {
                for i in 0..reader.get_count() {
                    let id = Id::entry(*idx, i as usize);
                    indices.globals.push(id);
                }
            }
            MemorySection(reader) => {
                for i in 0..reader.get_count() {
                    let id = Id::entry(*idx, i as usize);
                    indices.memories.push(id);
                }
            }
            TableSection(reader) => {
                for i in 0..reader.get_count() {
                    let id = Id::entry(*idx, i as usize);
                    indices.tables.push(id);
                }
            }
            CodeSectionStart { .. } | CodeSectionEntry(_) | FunctionSection(_) => {
                unreachable!("unexpected code or function section found");
            }
            _ => (),
        }
    }
    if let (Some(FuncSection(_, function_section)), Some(CodeSection(code_idx, _))) = (
        module.function_section.as_ref(),
        module.code_section.as_ref(),
    ) {
        indices.code = Some(*code_idx);
        for i in 0..function_section.get_count() {
            let id = Id::entry(*code_idx, i as usize);
            indices.functions.push(id);
        }
    }

    match (module.function_section, module.code_section) {
        (Some(function_section), Some(code_section)) => {
            (function_section, code_section).parse_edges(items, &indices)?
        }
        _ => panic!("function or code section is missing"),
    };
    for IndexedSection(idx, section) in module.sections {
        use Payload::*;
        match section {
            CustomSection { name, .. } => {
                CustomSectionReader(name, data).parse_edges(items, ())?;
            }
            TypeSection(mut reader) => reader.parse_edges(items, ())?,
            ImportSection(mut reader) => reader.parse_edges(items, ())?,
            TableSection(mut reader) => reader.parse_edges(items, ())?,
            MemorySection(mut reader) => reader.parse_edges(items, ())?,
            GlobalSection(mut reader) => reader.parse_edges(items, ())?,
            ExportSection(mut reader) => reader.parse_edges(items, (&indices, idx))?,
            StartSection { range, func, .. } => {
                WrappedStartSection(range).parse_edges(items, (&indices, idx, func))?
            }
            ElementSection(mut reader) => reader.parse_edges(items, (&indices, idx))?,
            DataSection(mut reader) => reader.parse_edges(items, ())?,
            DataCountSection { range, .. } => {
                WrappedDataCountSection(range).parse_edges(items, ())?
            }
            CodeSectionStart { .. } | CodeSectionEntry(_) | FunctionSection(_) => {
                unreachable!("unexpected code or function section found")
            }
            _ => (),
        }
    }

    Ok(())
}

fn read_module<'a, F>(mut data: &'a [u8], mut callback: F) -> Result<(), traits::Error>
where
    F: FnMut(usize, Payload<'a>) -> Result<(), traits::Error>,
{
    let mut parser = Parser::new(0);
    let mut stack = Vec::new();

    loop {
        let (payload, consumed) = match parser.parse(data, true)? {
            Chunk::NeedMoreData(_) => unreachable!("we set `eof` to true."),
            Chunk::Parsed { consumed, payload } => (payload, consumed),
        };

        use Payload::*;
        match payload {
            // When parsing nested modules we need to switch which
            // `Parser` we're using.
            ModuleSectionStart { .. } => {}
            ModuleSectionEntry {
                parser: subparser, ..
            } => {
                stack.push(parser);
                parser = subparser;
            }

            // Once we've reached the end of a module we either resume
            // at the parent module or we break out of the loop because
            // we're done.
            End => {
                if let Some(parent_parser) = stack.pop() {
                    parser = parent_parser;
                } else {
                    break;
                }
            }

            // All other sections are forwarded to the caller.
            section => callback(consumed, section)?,
        }

        data = &data[consumed..];
    }

    Ok(())
}

fn parse_module(data: &[u8]) -> Result<ParseResult, traits::Error> {
    let mut result = ParseResult::default();
    let mut idx = 0;

    // The function and code sections must be handled differently, so these
    // are not placed in the same `sections` array as the rest.
    read_module(data, |size, section| {
        result.sizes.insert(idx, size as u32);
        match section {
            wasmparser::Payload::FunctionSection(reader) => {
                result.function_section = Some(FuncSection(idx, reader));
                idx += 1;
            }
            wasmparser::Payload::CodeSectionStart { count, .. } => {
                result.code_section = Some(CodeSection(idx, Vec::with_capacity(count as usize)));
                idx += 1;
            }
            wasmparser::Payload::CodeSectionEntry(body) => {
                result.code_section.as_mut().unwrap().1.push((size as u32, body))
                // no index increment as code section entries are not top level
            }
            _ => {
                result.sections.push(IndexedSection(idx, section));
                idx += 1;
            }
        };
        Ok(())
    })?;

    Ok(result)
}

fn get_section_name(section: &wasmparser::Payload<'_>) -> String {
    use Payload::*;
    match section {
        CustomSection { name, .. } => {
            format!("custom section '{}' headers", name)
        }
        TypeSection(_) => "type section headers".to_string(),
        ImportSection(_) => "import section headers".to_string(),
        FunctionSection(_) => "function section headers".to_string(),
        TableSection(_) => "table section headers".to_string(),
        MemorySection(_) => "memory section headers".to_string(),
        GlobalSection(_) => "global section headers".to_string(),
        ExportSection(_) => "export section headers".to_string(),
        StartSection { .. } => "start section headers".to_string(),
        ElementSection(_) => "element section headers".to_string(),
        CodeSectionStart { .. } => "code section headers".to_string(),
        DataSection(_) => "data section headers".to_string(),
        DataCountSection { .. } => "data count section headers".to_string(),
        _ => "unknown section".to_string(),
    }
}

fn parse_names_section<'a>(
    indexed_sections: &[IndexedSection<'a>],
) -> Result<HashMap<usize, &'a str>, traits::Error> {
    let mut names = HashMap::new();
    for IndexedSection(_, section) in indexed_sections.iter() {
        if let Payload::CustomSection {
            name: "name", data, ..
        } = section
        {
            for subsection in wasmparser::NameSectionReader::new(data, 0)? {
                let f = match subsection? {
                    wasmparser::Name::Function(f) => f,
                    _ => continue,
                };
                let mut map = f.get_map()?;
                for _ in 0..map.get_count() {
                    let naming = map.read()?;
                    names.insert(naming.index as usize, naming.name);
                }
            }
        }
    }
    Ok(names)
}

fn count_imported_functions<'a>(
    indexed_sections: &[IndexedSection<'a>],
) -> Result<usize, traits::Error> {
    let mut imported_functions = 0;
    for IndexedSection(_, section) in indexed_sections.iter() {
        if let Payload::ImportSection(reader) = section {
            for import in reader.clone() {
                if let wasmparser::ImportSectionEntryType::Function(_) = import?.ty {
                    imported_functions += 1;
                }
            }
        }
    }
    Ok(imported_functions)
}

fn iterate_with_size<'a, S: SectionWithLimitedItems + SectionReader>(
    s: &'a mut S,
) -> impl Iterator<Item = Result<(S::Item, u32), traits::Error>> + 'a {
    let count = s.get_count();
    (0..count).map(move |i| {
        let start = s.original_position();
        let item = s.read()?;
        let size = (s.original_position() - start) as u32;
        if i == count - 1 {
            s.ensure_end()?;
        }
        Ok((item, size))
    })
}

fn ty2str(t: Type) -> &'static str {
    match t {
        Type::I32 => "i32",
        Type::I64 => "i64",
        Type::F32 => "f32",
        Type::F64 => "f64",
        Type::V128 => "v128",
        Type::FuncRef => "funcref",
        Type::ExnRef | Type::ExternRef => "extref",
        Type::Func | Type::EmptyBlockType => "?",
    }
}

impl<'a> Parse<'a> for (FuncSection<'a>, CodeSection<'a>) {
    type ItemsExtra = (usize, &'a HashMap<usize, &'a str>, &'a HashMap<usize, u32>);

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (imported_functions, names, sizes): Self::ItemsExtra,
    ) -> Result<(), traits::Error> {
        let (FuncSection(func_section_idx, func_reader), CodeSection(code_section_idx, bodies)) =
            self;

        let func_items: Vec<ir::Item> = iterate_with_size(func_reader)
            .enumerate()
            .map(|(i, func)| {
                let (_func, size) = func?;
                let id = Id::entry(*func_section_idx, i);
                let name = format!("func[{}]", i);
                let item = ir::Item::new(id, name, size, ir::Misc::new());
                Ok(item)
            })
            .collect::<Result<_, traits::Error>>()?;

        let code_items: Vec<ir::Item> = bodies
            .iter()
            .zip(func_items.into_iter())
            .enumerate()
            .map(|(i, (body, func))| {
                let (size, _) = body;
                let id = Id::entry(*code_section_idx, i);
                let name = names
                    .get(&(i + imported_functions))
                    .map_or_else(|| format!("code[{}]", i), |name| name.to_string());
                let code = ir::Code::new(&name);
                let item = ir::Item::new(id, name, size + func.size(), code);
                Ok(item)
            })
            .collect::<Result<_, traits::Error>>()?;

        let start = items.size_added();
        let name = "code section headers".to_string();
        for item in code_items.into_iter() {
            items.add_item(item);
        }
        let id = Id::section(*code_section_idx);
        let added = items.size_added() - start;
        let size = sizes
            .get(&code_section_idx)
            .ok_or_else(|| traits::Error::with_msg("Could not find section size"))?
            + sizes
                .get(&func_section_idx)
                .ok_or_else(|| traits::Error::with_msg("Could not find section size"))?;
        assert!(added <= size);
        items.add_root(ir::Item::new(id, name, size - added, ir::Misc::new()));

        Ok(())
    }

    type EdgesExtra = &'a SectionIndices;

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        indices: Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        let (FuncSection(_, func_reader), CodeSection(code_section_idx, bodies)) = self;

        type Edge = (ir::Id, ir::Id);

        let mut edges: Vec<Edge> = Vec::new();

        // Function section reader parsing.
        for (func_i, type_ref) in iterate_with_size(func_reader).enumerate() {
            let (type_ref, _) = type_ref?;
            if let Some(type_idx) = indices.type_ {
                let type_id = Id::entry(type_idx, type_ref as usize);
                if let Some(code_idx) = indices.code {
                    let body_id = Id::entry(code_idx, func_i);
                    edges.push((body_id, type_id));
                }
            }
        }

        // Code section reader parsing.
        for (b_i, body) in bodies.iter().enumerate() {
            let (_, body) = body;
            let body_id = Id::entry(*code_section_idx, b_i);

            let mut cache = None;
            for op in body.get_operators_reader()? {
                let prev = cache.take();
                match op? {
                    Operator::Call { function_index } => {
                        let f_id = indices.functions[function_index as usize];
                        edges.push((body_id, f_id));
                    }

                    // TODO: Rather than looking at indirect calls, need to look
                    // at where the vtables get initialized and/or vtable
                    // indices get pushed onto the stack.
                    Operator::CallIndirect { .. } => continue,

                    Operator::GlobalGet { global_index } | Operator::GlobalSet { global_index } => {
                        let g_id = indices.globals[global_index as usize];
                        edges.push((body_id, g_id));
                    }

                    Operator::I32Load { memarg }
                    | Operator::I32Load8S { memarg }
                    | Operator::I32Load8U { memarg }
                    | Operator::I32Load16S { memarg }
                    | Operator::I32Load16U { memarg }
                    | Operator::I64Load { memarg }
                    | Operator::I64Load8S { memarg }
                    | Operator::I64Load8U { memarg }
                    | Operator::I64Load16S { memarg }
                    | Operator::I64Load16U { memarg }
                    | Operator::I64Load32S { memarg }
                    | Operator::I64Load32U { memarg }
                    | Operator::F32Load { memarg }
                    | Operator::F64Load { memarg } => {
                        if let Some(Operator::I32Const { value }) = prev {
                            if let Some(data_id) = items.get_data(value as u32 + memarg.offset) {
                                edges.push((body_id, data_id));
                            }
                        }
                    }
                    other => cache = Some(other),
                }
            }
        }

        edges
            .into_iter()
            .for_each(|(from, to)| items.add_edge(from, to));

        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::NameSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        let mut i = 0;
        while !self.eof() {
            let start = self.original_position();
            let subsection = self.read()?;
            let size = (self.original_position() - start) as u32;
            let name = match subsection {
                wasmparser::Name::Module(_) => "\"module name\" subsection",
                wasmparser::Name::Function(_) => "\"function names\" subsection",
                wasmparser::Name::Local(_) => "\"local names\" subsection",
                _ => continue,
            };
            let id = Id::entry(idx, i);
            items.add_root(ir::Item::new(id, name, size, ir::DebugInfo::new()));
            i += 1;
        }

        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for CustomSectionReader<'a> {
    type ItemsExtra = (usize, u32);

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (idx, size): (usize, u32),
    ) -> Result<(), traits::Error> {
        let name = self.0;
        if name == "name" {
            wasmparser::NameSectionReader::new(self.1, 0)?.parse_items(items, idx)?;
        } else {
            let id = Id::entry(idx, 0);
            let name = format!("custom section '{}'", self.0);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::TypeSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, ty) in iterate_with_size(self).enumerate() {
            let (ty, size) = ty?;
            let ty = if let TypeDef::Func(ty) = ty {
                ty
            } else {
                continue
            };
            let id = Id::entry(idx, i);

            let mut name = format!("type[{}]: (", i);
            for (i, param) in ty.params.iter().enumerate() {
                if i != 0 {
                    name.push_str(", ");
                }
                name.push_str(ty2str(*param));
            }
            name.push_str(") -> ");

            match ty.returns.len() {
                0 => name.push_str("nil"),
                1 => name.push_str(ty2str(ty.returns[0])),
                _ => {
                    name.push_str("(");
                    for (i, result) in ty.returns.iter().enumerate() {
                        if i != 0 {
                            name.push_str(", ");
                        }
                        name.push_str(ty2str(*result));
                    }
                    name.push_str(")");
                }
            }

            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ImportSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, imp) in iterate_with_size(self).enumerate() {
            let (imp, size) = imp?;
            let id = Id::entry(idx, i);
            let name = format!("import {}::{}", imp.module, imp.field.unwrap_or("()"));
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, (): ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::TableSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, entry) in iterate_with_size(self).enumerate() {
            let (_entry, size) = entry?;
            let id = Id::entry(idx, i);
            let name = format!("table[{}]", i);
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::MemorySectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, mem) in iterate_with_size(self).enumerate() {
            let (_mem, size) = mem?;
            let id = Id::entry(idx, i);
            let name = format!("memory[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::GlobalSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, g) in iterate_with_size(self).enumerate() {
            let (g, size) = g?;
            let id = Id::entry(idx, i);
            let name = format!("global[{}]", i);
            let ty = ty2str(g.ty.content_type).to_string();
            items.add_item(ir::Item::new(id, name, size, ir::Data::new(Some(ty))));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ExportSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, exp) in iterate_with_size(self).enumerate() {
            let (exp, size) = exp?;
            let id = Id::entry(idx, i);
            let name = format!("export \"{}\"", exp.field);
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        for (i, exp) in iterate_with_size(self).enumerate() {
            let (exp, _) = exp?;
            let exp_id = Id::entry(idx, i);
            match exp.kind {
                wasmparser::ExternalKind::Function => {
                    items.add_edge(exp_id, indices.functions[exp.index as usize]);
                }
                wasmparser::ExternalKind::Table => {
                    items.add_edge(exp_id, indices.tables[exp.index as usize]);
                }
                wasmparser::ExternalKind::Memory => {
                    items.add_edge(exp_id, indices.memories[exp.index as usize]);
                }
                wasmparser::ExternalKind::Global => {
                    items.add_edge(exp_id, indices.globals[exp.index as usize]);
                },
                _ => (),
            }
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for WrappedStartSection {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        let size = (self.0.end - self.0.start) as u32;
        let id = Id::section(idx);
        let name = "\"start\" section";
        items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize, u32);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx, func_index): Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        items.add_edge(Id::section(idx), indices.functions[func_index as usize]);
        Ok(())
    }
}

impl<'a> Parse<'a> for WrappedDataCountSection {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        let size = (self.0.end - self.0.start) as u32;
        let id = Id::section(idx);
        let name = "\"data count\" section";
        items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _items: &mut ir::ItemsBuilder, (): ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ElementSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, elem) in iterate_with_size(self).enumerate() {
            let (_elem, size) = elem?;
            let id = Id::entry(idx, i);
            let name = format!("elem[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        for (i, elem) in iterate_with_size(self).enumerate() {
            let (elem, _size) = elem?;
            let elem_id = Id::entry(idx, i);

            match elem.kind {
                wasmparser::ElementKind::Active { table_index, .. } => {
                    items.add_edge(indices.tables[table_index as usize], elem_id);
                }
                wasmparser::ElementKind::Passive | wasmparser::ElementKind::Declared => {}
            }
            for func_idx in elem.items.get_items_reader()? {
                let func_idx = func_idx?;
                if let wasmparser::ElementItem::Func(func_idx) = func_idx {
                    items.add_edge(elem_id, indices.functions[func_idx as usize]);
                }
            }
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::DataSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, d) in iterate_with_size(self).enumerate() {
            let (d, size) = d?;
            let id = Id::entry(idx, i);
            let name = format!("data[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Data::new(None)));

            // Get the constant address (if any) from the initialization
            // expression.
            if let wasmparser::DataKind::Active { init_expr, .. } = d.kind {
                let mut iter = init_expr.get_operators_reader();
                let offset = match iter.read()? {
                    Operator::I32Const { value } => Some(i64::from(value)),
                    Operator::I64Const { value } => Some(value),
                    _ => None,
                };

                if let Some(off) = offset {
                    let length = d.data.len(); // size of data
                    items.link_data(off, length, id);
                }
            }
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}
