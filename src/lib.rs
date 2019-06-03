use goblin::pe::{PE, utils};
use scroll::Pread;
use scroll;
use goblin;

pub mod error;

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

    fn parse(data: &Vec<u8>, offset: &mut usize) -> Result<ResourceDir, scroll::Error> {
        Ok(ResourceDir {
            file_offset: *offset,
            characteristics: data.gread_with(offset, scroll::LE)?,
            time_date_stamp: data.gread_with(offset, scroll::LE)?,
            major_version: data.gread_with(offset, scroll::LE)?,
            minor_version: data.gread_with(offset, scroll::LE)?,
            number_of_named_entries: data.gread_with(offset, scroll::LE)?,
            number_of_id_entries: data.gread_with(offset, scroll::LE)?,
            entries: Vec::new(),
        })
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
    fn parse(data: &Vec<u8>, offset: &mut usize) -> Result<ResourceDirEntry, scroll::Error> {
        Ok(ResourceDirEntry {
            file_offset: *offset,
            name: data.gread_with(offset, scroll::LE)?,
            offset_to_data: data.gread_with(offset, scroll::LE)?,
        })
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
    fn parse(data: &Vec<u8>, offset: &mut usize) -> Result<ResourceDataEntry, scroll::Error> {
        Ok(ResourceDataEntry {
            file_offset: *offset,
            offset_to_data: data.gread_with(offset, scroll::LE)?,
            size: data.gread_with(offset, scroll::LE)?,
            code_page: data.gread_with(offset, scroll::LE)?,
            reserved: data.gread_with(offset, scroll::LE)?,
        })
    }
}

/// Reads a resource directory and it's entries and increments the offset.
///
/// # Examples
///
/// ```
/// let resource_dir = read_dir(&buffer, &mut offset);
/// ```
fn read_dir(bytes: &Vec<u8>, offset: &mut usize) -> Result<ResourceDir, scroll::Error> {
    let mut rdir_root = ResourceDir::parse(&bytes, offset)?;

    // Type Dir
    let num_entries = rdir_root.num_of_entries() as usize;
    for _ in 0..num_entries {
        rdir_root.entries.push(ResourceDirEntry::parse(&bytes, offset)?);
    }
    Ok(rdir_root)
}

// If the length is an odd number last byte of information will be lost.
fn convert_to_u16(u8_data: &[u8]) -> Vec<u16> {
    let mut i = 0;
    let mut u16_data: Vec<u16> = Vec::new();
    let data_len = u8_data.len();
    while i < u8_data.len() {
        if i+1 >= data_len {
            break;
        }
        let number = ((u8_data[i+1] as u16) << 8) | u8_data[i] as u16;
        u16_data.push(number);
        i += 2;
    }
    u16_data
}

fn parse_strings(data: &[u8]) -> String {
    let mut i = 0;
    let mut error_count = 0;
    let mut output = String::new();
    let data_u16 = convert_to_u16(data);
    let data_len = data_u16.len();
    while i < data_len {
        let len = data_u16[i] as usize;

        i += 1;
        if 0 < len && len < data_len {
            match String::from_utf16(&data_u16[i..i+len]) {
                Ok(string) => {
                    output.push_str(&string);
                },
                Err(_) => error_count += 1,
            };
            if error_count > 2 {
                break;
            }
            i += len;
        }
        // counter += 1;
    }
    output
}

// const RESOURCE_DIR_SIZE: usize = 16;
// const RESOURCE_DIR_ENTRY_SIZE: usize = 8;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;

pub fn get_strings(buffer: &Vec<u8>) -> Result<String, error::Error> {
    let pe = PE::parse(&buffer)?;
    let optional_header = pe.header.optional_header.ok_or(error::Error::OptionalHeader)?;
    let file_alignment = optional_header.windows_fields.file_alignment;
    let sections = &pe.sections;
    let rsrc = optional_header.data_directories.get_resource_table().ok_or(error::Error::DataDir)?;
    let rva = rsrc.virtual_address as usize;
    let mut base_offset = utils::find_offset(rva, sections, file_alignment).ok_or(error::Error::Offset(rva))?;

    // Type dir
    let rdir_root = read_dir(&buffer, &mut base_offset)?;

    // Name Dir
    let num_entries = rdir_root.num_of_entries() as usize;
    let mut named_dirs: Vec<ResourceDir> = Vec::new();
    let mut target_dir_index: Vec<usize> = Vec::new();
    for i in 0..num_entries {
        // 0x6 is the id of Strings Table, 0xb is the id of Message Table
        if rdir_root.entries[i].name == 0x6 || rdir_root.entries[i].name == 0xb {
            target_dir_index.push(i);
        }
        named_dirs.push(read_dir(&buffer, &mut base_offset)?);
    }

    // Lang Dir
    let mut lang_dirs: Vec<ResourceDir> = Vec::new();
    for rdir in &named_dirs {
        for _ in &rdir.entries {
            lang_dirs.push(read_dir(&buffer, &mut base_offset)?);
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

    let mut ret_str = String::new();
    // This code will not work as intended if there is both string table and message table sections
    // in the mui file and they are not right next to each other.
    for i in 0..skip_count+read_count {
        if i >= skip_count {
            let data_entry = ResourceDataEntry::parse(&buffer, &mut base_offset)?;
            let start_rva = data_entry.offset_to_data as usize;
            let start_addr = utils::find_offset(start_rva, sections, file_alignment).ok_or(error::Error::Offset(start_rva))?;
            let end_rva = (data_entry.offset_to_data+data_entry.size) as usize;
            let end_addr = utils::find_offset(end_rva, sections, file_alignment).ok_or(error::Error::Offset(end_rva))?;
            let data = &buffer[start_addr..end_addr];

            ret_str.push_str(&parse_strings(data));
        } else {
            // Skip data until we reach out desired data entries.
            base_offset += RESOURCE_DATA_ENTRY_SIZE;
        }
    }
    Ok(ret_str)
}
