use std::process::ExitCode;
use std::path::{Path, PathBuf};
use std::str::CharIndices;
use std::collections::HashMap;
use std::ops::Range;
use std::io::*;

const USAGE: &str = "USAGE:
    symtool extract [args] <path>
        Finds and prints all function symbols in passed directory or file.
        
        -h      Only use header files
        
    symtool addr <mapfile>
        For each piped line, find the address of that symbol given in the passed mapfile, then print the symbol and the address.

        The mapfile format is flexible. The only requirement is that the symbol and the address are on the same line.
        
    symtool update <mapfile>
        For each piped line, find the symbol and address on that line update the passed mapfile with the symbol.

        The input and output map files formats are flexible.
        The only requirement is that the symbol and the address are on the same line.
";

macro_rules! log_err {
    ($($v:tt)*) => {{
        let mut stdout = stdout().lock();
        
        // print command that issued error
        for arg in std::env::args_os() {
            stdout.write_all(arg.as_encoded_bytes()).unwrap();
            stdout.write_all(b" ").unwrap();
        }
        
        // print error
        stdout.write_all(b"| ").unwrap();
        write!(&mut stdout, $($v)*).unwrap();
        stdout.write(b"\n").unwrap();
        stdout.flush().unwrap();
    }}
}

fn main() -> ExitCode {
    let args = std::env::args().collect::<Vec<_>>();
    
    if args.len() <= 1 {
        print!("{}", USAGE);
        return ExitCode::SUCCESS;
    }
    
    match args[1].as_str() {
        "extract" => extract(&args[2..]),
        "addr" => addr(&args[2..]),
        "update" => update(&args[2..]),
        _ => {
            print!("{}", USAGE);
            return ExitCode::FAILURE;
        }
    }
}

// Subcommands --------------------------------------------------------

fn extract(args: &[String]) -> ExitCode {
    if args.is_empty() {
        print!("{}", USAGE);
        return ExitCode::FAILURE;
    }
    
    let (search_path, args) = args.split_last().unwrap();
    let paths = files_in_path(Path::new(search_path));
    
    let mut header_only = false;
    for arg in args {
        match arg.as_str() {
            "-h" => header_only = true,
            arg => log_err!("Unknown argument '{}'", arg),
        }
    }
    
    let extensions: &[&str] = if header_only { &["h"] } else { &["c", "h", "cc"] };
    
    for path in paths {
        let Some(ext) = path.extension() else { continue };
        
        let mut ext_good = false;
        for allowed_ext in extensions {
            if ext == *allowed_ext { ext_good = true; break } 
        }
        
        if !ext_good { continue }

        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                log_err!("Failed to read file {}: {}", path.display(), e);
                continue
            }
        };
        
        let mut src_iter = src.char_indices();
        let src_iter = &mut src_iter;
        
        let mut stdout = stdout().lock();
        
        while !src_iter.as_str().is_empty() {
            'find_fn: {
                take_whitespace(src_iter);
                
                // take function name
                let fn_name = take_c_token(src_iter);
                if fn_name.is_empty() { break 'find_fn; }
                
                // ensure function call
                take_whitespace(src_iter);
                if take_while(src_iter, |c| c == '(').is_empty() { break 'find_fn; }
                
                // filter function pointers/typedefs
                take_whitespace(src_iter);
                if !take_while(src_iter, |c| c == '*').is_empty() { break 'find_fn; }
                
                // filter builtins
                match fn_name {
                    "if" | "for" | "while" | "return" | "switch" | "case"
                        | "sizeof" | "alignof" | "__attribute__" => break 'find_fn,
                    _ => {},
                }
                
                let res = stdout.write_all(fn_name.as_bytes())
                    .and_then(|()| stdout.write_all(b"\n"));

                match res {
                    Err(e) if e.kind() == ErrorKind::BrokenPipe => return ExitCode::SUCCESS,
                    Err(e) => {
                        drop(stdout);
                        log_err!("Could not write to stdout: {}", e);
                        return ExitCode::FAILURE;
                    }
                    Ok(_) => {}
                }
            }
            
            // skip until next symbol, then try again
            take_while(src_iter, |c| !c.is_ascii_alphabetic() && c != '_');
        }
    }
    
    ExitCode::SUCCESS
}

fn addr(args: &[String]) -> ExitCode {
    if args.is_empty() {
        print!("{}", USAGE);
        return ExitCode::FAILURE;
    }
    
    let mapfile_path = Path::new(&args[0]);
    let mapfile = match std::fs::read_to_string(mapfile_path) {
        Ok(mapfile) => mapfile,
        Err(e) => {
            log_err!("Failed to read map file {}: {}", mapfile_path.display(), e);
            return ExitCode::FAILURE;
        }
    };
    
    let mut maplookup = HashMap::<&str, u32>::new();
    for line in mapfile.lines() {
        if let Some(info) = line_symaddr(line) {
            maplookup.insert(info.symbol, info.addr);
        }
    }
    
    // lookup symbols
    let stdin = stdin().lock();
    for line in stdin.lines() {
        let Ok(line) = line else { continue };
        let sym = line.trim();
        if let Some(addr) = maplookup.get(sym) {
            println!("{} {:08X}", sym, addr);
        }
    }
    
    ExitCode::SUCCESS
}

fn update(args: &[String]) -> ExitCode {
    if args.is_empty() {
        print!("{}", USAGE);
        return ExitCode::FAILURE;
    }
    
    let mapfile_path = Path::new(&args[0]);
    let mut mapfile = match std::fs::read_to_string(mapfile_path) {
        Ok(mapfile) => mapfile,
        Err(e) => {
            log_err!("Failed to read map file {}: {}", mapfile_path.display(), e);
            return ExitCode::FAILURE;
        }
    };
    
    let mut updates = HashMap::<u32, String>::new();
    let stdin = stdin().lock();
    for line in stdin.lines() {
        let Ok(line) = line else { continue };

        if let Some(info) = line_symaddr(&line) {
            updates.insert(info.addr, info.symbol.to_string());
        }
    }

    if updates.is_empty() { return ExitCode::SUCCESS }

    let mut i = mapfile.len();
    while let Some((_, line)) = mapfile[..i].rsplit_once('\n') {
        let line_start = i - line.len();

        'check_line: {
            let (addr, range) = match line_symaddr(line) {
                Some(info) => (info.addr, info.symbol_range),
                None => break 'check_line,
            };
            let Some(new_symbol) = updates.get(&addr) else { break 'check_line };
            
            let sym_range = (line_start+range.start)..(line_start+range.end);
            println!("{} -> {}", &mapfile[sym_range.clone()], new_symbol);
            mapfile.replace_range(sym_range, new_symbol);
        }
        
        i = line_start;
        if i != 0 { i -= 1; } else { break; }
    }
    
    if let Err(e) = std::fs::write(mapfile_path, &mapfile) {
        log_err!("Failed to write map file {}: {}", mapfile_path.display(), e);
        return ExitCode::FAILURE;
    }
    
    ExitCode::SUCCESS
}

// Helper functions --------------------------------------------------------

struct SymAddr<'a> {
    addr: u32,
    _addr_range: Range<usize>,

    symbol: &'a str,
    symbol_range: Range<usize>,
}

fn line_symaddr(line: &str) -> Option<SymAddr> {
    // find address ----------------------------------
    
    let mut addr = 0;
    let mut addr_start = 0;
    'addr_window: for (i, addr_bytes) in line.as_bytes().windows(8).enumerate() {
        let mut cur_addr = 0;
        for b in addr_bytes {
            let n = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => continue 'addr_window,
            };
            cur_addr = (cur_addr << 4) | n;
        }
        
        if 0x80000000 <= cur_addr && cur_addr < 0x81800000 {
            addr = cur_addr;
            addr_start = i;
            break;
        }
    }
    
    // addr not found on this line
    if addr == 0 { return None }
    
    // find symbol ----------------------------------
    
    let mut chars = line.char_indices();
    
    let start_i = 'find_start_i: loop {
        loop {
            match chars.next() {
                // don't parse hex numbers as a symbol 
                Some((_, c)) if c.is_numeric() => break,

                Some((i, c)) if c.is_ascii_alphabetic() || c == '_' => break 'find_start_i i,
                None => return None,
                _ => {}
            }
        }
        
        // skip hex digits
        loop {
            match chars.next() {
                Some((_, c)) if !c.is_ascii_hexdigit() => break,
                None => return None,
                _ => {}
            }
        }
    };
    
    let end_i = loop {
        match chars.next() {
            Some((_, c)) if c.is_ascii_alphanumeric() || c == '_' => {},
            Some((i, _)) => break i,
            None => break chars.offset(),
        }
    };
    
    let symbol = &line[start_i..end_i];
    
    Some(SymAddr {
        addr,
        _addr_range: addr_start..addr_start+8,
        symbol,
        symbol_range: start_i..end_i,
    })
}

fn take_while<'a>(src: &mut CharIndices<'a>, f: fn(char) -> bool) -> &'a str {
    let start_i = src.offset();
    let rest = src.as_str();

    loop {
        match src.as_str().chars().next() {
            Some(c) if f(c) => src.next(),
            _ => break,
        };
    }

    let end_i = src.offset();
    &rest[..(end_i - start_i)]
}

fn take_whitespace<'a>(src: &mut CharIndices<'a>) -> &'a str {
    take_while(src, |c| c.is_ascii_whitespace())
}

fn take_c_token<'a>(src: &mut CharIndices<'a>) -> &'a str {
    let start_i = src.offset();
    let rest = src.as_str();
    
    'check_token: {
        // initial character check to prevent starting with number
        match src.as_str().chars().next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => src.next(),
            _ => break 'check_token,
        };

        // allow numbers in proceeding characters
        loop {
            match src.as_str().chars().next() {
                Some(c) if c.is_ascii_alphanumeric() || c == '_' => src.next(),
                _ => break 'check_token,
            };
        }
    }

    let end_i = src.offset();
    &rest[..(end_i - start_i)]
}

fn files_in_path(root_path: &Path) -> Vec<PathBuf> {
    if root_path.is_file() {
        return vec![root_path.to_owned()];
    }
    
    let mut files = Vec::new();
    let mut dir_stack = Vec::new();
    dir_stack.push(root_path.to_owned());
    
    while let Some(path) = dir_stack.pop() {
        let iter = match std::fs::read_dir(&path) {
            Ok(iter) => iter,
            Err(e) => {
                log_err!("Failed to read directory {}: {}", path.display(), e);
                continue
            }
        };

        for entry in iter {
            let Ok(entry) = entry else { continue };
            let Ok(metadata) = entry.metadata() else { continue };
            
            let name = entry.file_name();
            let new_path = path.join(name);
            
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                dir_stack.push(new_path);
            } else if file_type.is_file() {
                files.push(new_path);
            }
        }
    }
    
    files
}
