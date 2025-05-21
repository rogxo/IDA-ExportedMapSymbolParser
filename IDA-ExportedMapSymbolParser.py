import idaapi
import idautils
import idc
import re

def extract_names_and_rva_base(file_path):
    # Updated regular expression pattern to match the new format:
    # e.g., " 0000000E:0000000000151DE0     hexdigits"
    # Group 1: Segment ID (e.g., "0000000E") - not used for renaming directly but captured
    # Group 2: Address/Offset (e.g., "0000000000151DE0")
    # Group 3: Symbol Name (e.g., "hexdigits")
    pattern = r"\s*([a-fA-F0-9]+):([a-fA-F0-9]+)\s+(.+)"
    results = []

    # Open the file and read line by line
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                # Extract groups based on the new pattern
                segment_id, address_str, symbol_name = match.groups()
                
                # The address we need for IDA is the offset part (address_str)
                # The symbol name is the last captured group, strip any trailing whitespace
                name = symbol_name.strip()
                rva_base_address = int(address_str, 16)
                
                results.append((name, rva_base_address))
    return results

def rename_symbols_from_map():
    # Use idaapi.ask_file to show a file selection dialog for choosing a .map file
    map_file_path = idaapi.ask_file(0, "*.map", "Please select a .map file to parse")
    if map_file_path:
        extracted_data = extract_names_and_rva_base(map_file_path)
        print(f"[ParseMap] Found {len(extracted_data)} potential symbols in the .map file.")
        
        renamed_count = 0
        for name, rva_base in extracted_data:
            # Ensure the name is not empty after stripping
            if not name:
                print(f"[ParseMap] Warning: Empty name for address 0x{rva_base:X}, skipping.")
                continue

            # Use idaapi.set_name to rename the corresponding address, ensuring the address is valid
            # Check if the address belongs to a valid segment
            if idc.get_segm_name(rva_base) is not None:
                # Sanitize name if necessary (IDA has restrictions on characters in names)
                # For example, replacing characters not allowed or too long.
                # This is a basic sanitization, more complex rules might be needed.
                sanitized_name = idaapi.validate_name(name, idaapi.VNT_IDENT)
                if not sanitized_name: # If validate_name returns empty, it means it couldn't make it valid easily
                    sanitized_name = idaapi.make_name_presentable(name, idaapi.VNT_IDENT)
                    # Fallback if make_name_presentable also fails or to ensure it's somewhat valid
                    if not sanitized_name:
                         sanitized_name = f"sym_{rva_base:X}" # Default name if sanitization fails badly

                if idaapi.set_name(rva_base, sanitized_name, idaapi.SN_NOWARN | idaapi.SN_FORCE):
                    renamed_count += 1
                else:
                    # If set_name failed, it might be due to an existing name that IDA protects,
                    # or other reasons. SN_FORCE should typically overcome most simple cases.
                    print(f"[ParseMap] Failed to set name '{sanitized_name}' at 0x{rva_base:X}. Current name: '{idc.get_name(rva_base)}'")
            else:
                print(f"[ParseMap] Address 0x{rva_base:X} (for symbol '{name}') is not in a valid segment, skipping.")
                
        print(f"[ParseMap] Processed {len(extracted_data)} symbols. Successfully renamed {renamed_count} symbols.")
    else:
        print("[ParseMap] No .map file selected.")

class ParseMapPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = 'Parse .map file and rename symbols'
    help = 'Select a .map file to parse symbol names and apply them to the database.'
    wanted_name = 'Parse MAP File (for RVA+Name)'
    wanted_hotkey = 'Alt-M' # Example hotkey

    def init(self):
        print("[ParseMap] Plugin initialized.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("[ParseMap] Plugin run.")
        rename_symbols_from_map()

    def term(self):
        print("[ParseMap] Plugin terminated.")
        pass

def PLUGIN_ENTRY():
    try:
        return ParseMapPlugin()
    except Exception as err:
        import traceback
        print('[ParseMap] Error loading plugin: %s\n%s' % (str(err), traceback.format_exc()))
        # Do not raise here, as it might prevent IDA from loading other plugins or itself properly.
        # Simply return None or an error indicator if the plugin API supports it.
        return None


# This part allows the script to be run directly from IDA's script execution (Alt+F7 or Shift+F2)
# without needing to be a full plugin, for testing purposes.
def main():
    print("[ParseMap] Running as script...")
    rename_symbols_from_map()

if __name__ == '__main__':
    # When run as a script from IDA (e.g. Shift+F2), this block will execute.
    # If loaded as a plugin, PLUGIN_ENTRY is the entry point.
    main()
