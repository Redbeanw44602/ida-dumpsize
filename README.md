# ida-dumpsize
This is an IDA script that exports reliable structure size information based on the results of the Hex-Rays decompiler.

### Limitations
 - Make sure you have a license for the Hex-Rays decompiler.
 - Analysis based on `operator new` calls.
 - If the Hex-Rays results have errors, they cannot be fixed.
 - The debugging information contains at least a symbol table to identify the class names.

### Usage
1. Download the latest release.
2. Go *File->Script file...* or use `Alt+F7`.
3. Select `dumpsize.py`, execute and wait.
4. The results will be saved in `dump.json` and the logs will be output to the console.

### TODO
- [ ] itanium support
- [ ] array & user-defined & aligned
- [ ] shared-ptr like

#### Sample Output: `dump.json`
```json
{
    "GrowingPlantFeature": 112,
    "Core::FileSystemInterfaceImpl": 24,
    "CodeBuilder::Manager": 40,
    "ImguiProfiler": 120,
    "std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>": 32,
    "EatBlockDefinition": 248,
    "LookAtActorGoal": 200,
    "Aquifer": 120,
    "DBChunkStorage": 584,
    "DiggerItemComponentLegacyFactoryData": 312,
    "Scripting::ClosureAny": 88,
    "ListTag": 40
}
```
