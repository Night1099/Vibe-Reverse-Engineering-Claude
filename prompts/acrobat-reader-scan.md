# Adobe Acrobat Reader Security Assessment

## Prompt

Copy the block below into a new Claude Code session to start the scan.

---

```
I have Adobe Acrobat Reader installed. Run a full security assessment targeting it for bounty-eligible vulnerabilities (Adobe HackerOne program: https://hackerone.com/adobe).

**Target path** (adjust to match your install):
- Windows: `C:\Program Files\Adobe\Acrobat Reader DC\Reader\`
- Relevant binaries: AcroRd32.exe, Acrobat.dll, AcroForm.api, JP2KLib.dll, CoolType.dll, AGM.dll, BIB.dll, ACE.dll

## Phase 1: Reconnaissance (run in parallel)

1. **Mitigation audit** — Run `python -m retools.mitigations "<install_path>" --recursive` to scan every PE in the Reader directory. Identify which DLLs have the weakest mitigations (missing CFG, no ASLR, no /GS). These are priority targets.

2. **Dangerous API scan** — For the 5 weakest-mitigated binaries, run `python -m retools.vulnscan <binary> scan --risk high`. Focus on:
   - Buffer overflow sinks (memcpy, strcpy, sprintf) reachable from PDF parsing
   - Format string bugs
   - Integer overflow in allocation sizes (malloc/HeapAlloc with attacker-controlled size)

3. **Attack surface mapping** — For each priority binary:
   - `python -m retools.vulnscan <binary> imports` to see the full dangerous import profile
   - `python -m retools.search <binary> strings -f "javascript,script,font,image,jpeg,jp2,stream,xref,trailer,catalog"` to find PDF-parsing related strings
   - `python -m retools.search <binary> imports -d msvcr` to check CRT version (older = more vulnerable)

4. **Compiler fingerprinting** — `python -m retools.sigdb fingerprint <binary>` on each target to identify compiler version, CRT, and link-time optimizations.

## Phase 2: Deep Analysis (delegate to static-analyzer)

For each high-value finding from Phase 1:

5. **Bootstrap the primary binary** — `bootstrap.py <binary> --project AcrobatReader` + `pyghidra_backend.py analyze` in parallel.

6. **Trace dangerous call sites** — For every high-risk vulnscan hit:
   - Decompile the calling function
   - Run `dataflow.py` backward slice on the size/length argument to see if it originates from file input
   - Follow the callgraph upward to see if it's reachable from a PDF parsing entry point
   - Classify: attacker-controlled size → buffer overflow, attacker-controlled format string → format string bug

7. **Focus areas for Acrobat Reader** — These subsystems historically produce bounty-winning bugs:
   - **Font parsing**: CoolType.dll, AGM.dll — Type1, TrueType, CFF, OpenType parsing
   - **Image codecs**: JP2KLib.dll — JPEG2000, also JBIG2, CCITT in the core
   - **JavaScript engine**: EScript.api — object lifecycle bugs (UAF, type confusion)
   - **XFA/form handling**: AcroForm.api — complex XML + layout engine
   - **Stream filters**: FlateDecode, LZWDecode, ASCIIHexDecode in the core PDF parser

## Phase 3: Fuzzing Prep

8. **Identify parser entry points** — Find functions that read from file/stream objects and parse structured data. These become fuzzing targets.

9. **Generate corpus** — Note the PDF features each parser handles so we can build targeted PDF corpus files (font-heavy, image-heavy, JavaScript-heavy, XFA-heavy).

10. **Set up crash monitoring** — `python -m retools.crashtriage watch ./crashes --binary <target_dll> --interval 5`

## Output

For each finding, record:
- Binary name + offset of vulnerable call site
- Vulnerability class (buffer overflow, format string, integer overflow, UAF)
- Data flow: how attacker input reaches the sink
- Mitigation status of the target binary
- Exploitability assessment
- Suggested fuzzing strategy to trigger it

Write findings to `patches/AcrobatReader/findings.md` and update `patches/AcrobatReader/kb.h` with discovered function names and types.
```

---

## What This Prompt Does

| Phase | Tools Used | Time | Output |
|-------|-----------|------|--------|
| Recon | mitigations, vulnscan, search, sigdb | 2-5 min | Priority target list ranked by weakness |
| Deep analysis | bootstrap, pyghidra, decompiler, dataflow, callgraph | 10-30 min | Confirmed attack paths from PDF input to dangerous sinks |
| Fuzzing prep | crashtriage watch, search strings | Ongoing | Parser entry points, corpus strategy, live crash monitoring |

## Customization

- **Different Adobe product**: Change the install path. Works for Acrobat Pro, Photoshop, InDesign, etc.
- **Non-Adobe target**: Replace the focus areas in Phase 2 step 7 with the target's known attack surface (e.g., for Foxit Reader: focus on JavaScript, annotation handling, U3D parsing).
- **Quick scan only**: Use just Phase 1 — takes under 5 minutes and gives you the mitigation weakness map + dangerous API call sites.
