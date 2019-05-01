use goblin::pe;
use goblin::pe::utils::find_offset;
use scroll::Pread;
use clap::{Arg, App, crate_version};
use std::fs::File;
use std::io::Read;
use std::process::exit;
use std::string::String;

#[derive(Debug)]
struct ResourceDir {
    // 0x400      0x0   Characteristics:               0x0
    // 0x404      0x4   TimeDateStamp:                 0x0        [Thu Jan  1 00:00:00 1970 UTC]
    // 0x408      0x8   MajorVersion:                  0x4
    // 0x40A      0xA   MinorVersion:                  0x0
    // 0x40C      0xC   NumberOfNamedEntries:          0x1
    // 0x40E      0xE   NumberOfIdEntries:             0x2
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    number_of_named_entries: u16,
    number_of_id_entries: u16,
    file_offset: usize,
    entries: Vec<ResourceDirEntry>,
}

impl ResourceDir {
    fn num_of_entries(&self) -> u16 {
        self.number_of_named_entries + self.number_of_id_entries
    }

    fn parse(data: &Vec<u8>, offset: &mut usize) -> ResourceDir {
        ResourceDir {
            file_offset: *offset,
            characteristics: data.gread_with(offset, scroll::LE).unwrap(),
            time_date_stamp: data.gread_with(offset, scroll::LE).unwrap(),
            major_version: data.gread_with(offset, scroll::LE).unwrap(),
            minor_version: data.gread_with(offset, scroll::LE).unwrap(),
            number_of_named_entries: data.gread_with(offset, scroll::LE).unwrap(),
            number_of_id_entries: data.gread_with(offset, scroll::LE).unwrap(),
            entries: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct ResourceDirEntry {
    // 0x410      0x0   Name:                          0x80000298
    // 0x414      0x4   OffsetToData:                  0x80000028
    name: u32,
    offset_to_data: u32,
    file_offset: usize,
}

impl ResourceDirEntry {
    fn parse(data: &Vec<u8>, offset: &mut usize) -> ResourceDirEntry {
        ResourceDirEntry {
            file_offset: *offset,
            name: data.gread_with(offset, scroll::LE).unwrap(),
            offset_to_data: data.gread_with(offset, scroll::LE).unwrap(),
        }
    }
}

#[derive(Debug)]
struct ResourceDataEntry {
    // 0x5D8      0x0   OffsetToData:                  0x22A0
    // 0x5DC      0x4   Size:                          0xB0
    // 0x5E0      0x8   CodePage:                      0x4E4
    // 0x5E4      0xC   Reserved:                      0x0
    offset_to_data: u32,
    size: u32,
    code_page: u32,
    reserved: u32,
    file_offset: usize,
}

impl ResourceDataEntry {
    fn parse(data: &Vec<u8>, offset: &mut usize) -> ResourceDataEntry {
        ResourceDataEntry {
            file_offset: *offset,
            offset_to_data: data.gread_with(offset, scroll::LE).unwrap(),
            size: data.gread_with(offset, scroll::LE).unwrap(),
            code_page: data.gread_with(offset, scroll::LE).unwrap(),
            reserved: data.gread_with(offset, scroll::LE).unwrap(),
        }
    }
}

/// Reads a resource directory and it's entries and increments the offset.
///
/// # Examples
///
/// ```
/// let resource_dir = read_dir(&buffer, &mut offset);
/// ```
fn read_dir(bytes: &Vec<u8>, offset: &mut usize) -> ResourceDir {
    let mut rdir_root = ResourceDir::parse(&bytes, offset);

    // Type Dir
    let num_entries = rdir_root.num_of_entries() as usize;
    for _ in 0..num_entries {
        rdir_root.entries.push(ResourceDirEntry::parse(&bytes, offset));
    }
    rdir_root
}

// const RESOURCE_DIR_SIZE: usize = 16;
// const RESOURCE_DIR_ENTRY_SIZE: usize = 8;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;

fn main() {
    let matches = App::new("MUI Strings")
                        .version(crate_version!())
                        .author("David Z. <david@dzhy.dev>")
                        .about("Get strings from the resource section of MUI files.")
                        .arg(Arg::with_name("file")
                            .short("f")
                            .long("file")
                            .required(true)
                            .help("The target file")
                            .takes_value(true))
                        .get_matches();

    let file_path = matches.value_of("file").unwrap();

    let mut fd = File::open(file_path).unwrap();
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer).unwrap();
    match pe::PE::parse(&buffer) {
        Ok(pe) => {
            let optional_header = pe.header.optional_header.expect("No optional header");
            let file_alignment = optional_header.windows_fields.file_alignment;
            let sections = &pe.sections;
            let rsrc = optional_header.data_directories.get_resource_table().unwrap();
            let rva = rsrc.virtual_address as usize;
            let mut base_offset = find_offset(rva, sections, file_alignment).unwrap();
            
            // Type dir
            let rdir_root = read_dir(&buffer, &mut base_offset);

            // Name Dir
            let num_entries = rdir_root.num_of_entries() as usize;
            let mut named_dirs: Vec<ResourceDir> = Vec::new();
            let mut target_dir_index: Vec<usize> = Vec::new();
            for i in 0..num_entries {
                // 0x6 is the id of Strings Table, 0xb is the id of Message Table
                if rdir_root.entries[i].name == 0x6 || rdir_root.entries[i].name == 0xb {
                    target_dir_index.push(i);
                }
                named_dirs.push(read_dir(&buffer, &mut base_offset));
            }

            // Lang Dir
            let mut lang_dirs: Vec<ResourceDir> = Vec::new();
            for rdir in &named_dirs {
                for _ in &rdir.entries {
                    lang_dirs.push(read_dir(&buffer, &mut base_offset));
                }
            }

            // Data Entry
            let mut skip_count = 0;
            let mut read_count = 0;
            for i in target_dir_index {
                read_count += named_dirs[i].num_of_entries();
                for j in 0..i {
                    skip_count += named_dirs[j].num_of_entries();
                }
            }

            // This code will not work as intended if there is both string table and message table sections
            // in the mui file and they are not right next to each other.
            for i in 0..skip_count+read_count {
                if i >= skip_count {
                    let data_entry = ResourceDataEntry::parse(&buffer, &mut base_offset);
                    let start_addr = find_offset(data_entry.offset_to_data as usize, sections, file_alignment).unwrap();
                    let end_addr = find_offset((data_entry.offset_to_data+data_entry.size) as usize, sections, file_alignment).unwrap();
                    let data = &buffer[start_addr..end_addr];
                    println!("{}", &String::from_utf8_lossy(&data));
                } else {
                    // Skip data until we reach out desired data entries.
                    base_offset += RESOURCE_DATA_ENTRY_SIZE;
                }
            }
        },
        Err(err) => {
            println!("err: {:?}", err);
            exit(1);
        }
    }
}
