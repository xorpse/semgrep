(*
   Copyright (c) 2025 Semgrep Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   version 2.1 as published by the Free Software Foundation.

   This library is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
   LICENSE for more details.
*)

(*****************************************************************************)
(* Purpose *)
(*****************************************************************************)
(* Unit tests demonstrating in-memory scanning capabilities.
 *
 * This module tests the ability to scan code from strings (in-memory content)
 * rather than from files on disk, including pattern matching. This is useful for:
 * - API/service integrations where content comes from HTTP requests
 * - Programmatic batch scanning of code snippets
 * - Editor/IDE integrations with unsaved buffers
 * - Testing without creating temporary files
 *)

let t = Testo.create

(*****************************************************************************)
(* Test: C++ in-memory scanning with pattern matching *)
(*****************************************************************************)

(* Test parsing C++ code from a string AND matching a rule against it *)
let test_cpp_in_memory_scan () =
  (* C++ code with some patterns we want to detect *)
  let content = {|
#include <iostream>
#include <cstdlib>

void unsafe_function() {
    char buffer[10];
    gets(buffer);  // Unsafe: should match our rule
}

void another_unsafe() {
    char buf[100];
    gets(buf);  // Another match
}

int main() {
    std::cout << "Hello" << std::endl;
    unsafe_function();
    return 0;
}
|} in
  let file = Fpath.v "test.cpp" in
  let lang = Lang.Cpp in

  (* Step 1: Parse the code from string *)
  let parse_result = Parse_target.just_parse_with_lang_from_string lang file content in
  assert (parse_result.ast <> []);
  assert (parse_result.errors = []);
  print_endline "  Step 1: Parsing succeeded";

  (* Step 2: Parse a pattern - detect calls to gets() which is unsafe *)
  let pattern_string = "gets($BUF)" in
  let pattern =
    match Parse_pattern.parse_pattern lang pattern_string with
    | Ok pat -> pat
    | Error msg -> failwith (Printf.sprintf "Failed to parse pattern: %s" msg)
  in
  print_endline "  Step 2: Pattern parsing succeeded";

  (* Step 3: Create a mini-rule for matching *)
  let rule = Mini_rule.{
    id = Rule_ID.of_string_exn "detect-unsafe-gets";
    pattern;
    inside = false;
    message = "Use of unsafe gets() function detected";
    metadata = None;
    severity = `Error;
    langs = [ lang ];
    pattern_string;
    fix = None;
    fix_regexp = None;
  } in
  print_endline "  Step 3: Mini-rule created";

  (* Step 4: Run pattern matching against the AST *)
  let matches = ref [] in
  let _results = Match_patterns.check
    ~hook:(fun pm -> matches := pm :: !matches)
    Rule_options.default
    [ rule ]
    (file, Origin.In_memory { name = Fpath.to_string file; content }, lang, parse_result.ast)
  in
  print_endline (Printf.sprintf "  Step 4: Pattern matching complete, found %d matches" (List.length !matches));

  (* Step 5: Verify we found the expected matches *)
  (* We expect 2 matches: one for each gets() call *)
  assert (List.length !matches = 2);

  (* Print match locations for verification *)
  List.iter (fun (pm : Core_match.t) ->
    let start_line = pm.range_loc |> fst |> fun loc -> loc.pos.Pos.line in
    print_endline (Printf.sprintf "    Match at line %d" start_line)
  ) !matches;

  print_endline "C++ in-memory scan: OK"

(*****************************************************************************)
(* Test: Python in-memory scanning with pattern matching *)
(*****************************************************************************)

let test_python_in_memory_scan () =
  (* Python code with security issues to detect *)
  let content = {|
import os

def run_command(cmd):
    os.system(cmd)  # Unsafe: command injection risk

def another_risky(user_input):
    os.system(user_input)  # Another match

def safe_function():
    print("Hello, World!")
|} in
  let file = Fpath.v "test.py" in
  let lang = Lang.Python in

  (* Step 1: Parse the code from string *)
  let parse_result = Parse_target.just_parse_with_lang_from_string lang file content in
  assert (parse_result.ast <> []);
  assert (parse_result.errors = []);
  print_endline "  Step 1: Parsing succeeded";

  (* Step 2: Parse a pattern - detect calls to os.system() *)
  let pattern_string = "os.system($CMD)" in
  let pattern =
    match Parse_pattern.parse_pattern lang pattern_string with
    | Ok pat -> pat
    | Error msg -> failwith (Printf.sprintf "Failed to parse pattern: %s" msg)
  in
  print_endline "  Step 2: Pattern parsing succeeded";

  (* Step 3: Create a mini-rule for matching *)
  let rule = Mini_rule.{
    id = Rule_ID.of_string_exn "detect-os-system";
    pattern;
    inside = false;
    message = "Use of os.system() detected - potential command injection";
    metadata = None;
    severity = `Warning;
    langs = [ lang ];
    pattern_string;
    fix = None;
    fix_regexp = None;
  } in
  print_endline "  Step 3: Mini-rule created";

  (* Step 4: Run pattern matching against the AST *)
  let matches = ref [] in
  let _results = Match_patterns.check
    ~hook:(fun pm -> matches := pm :: !matches)
    Rule_options.default
    [ rule ]
    (file, Origin.In_memory { name = Fpath.to_string file; content }, lang, parse_result.ast)
  in
  print_endline (Printf.sprintf "  Step 4: Pattern matching complete, found %d matches" (List.length !matches));

  (* Step 5: Verify we found the expected matches *)
  (* We expect 2 matches: one for each os.system() call *)
  assert (List.length !matches = 2);

  (* Print match locations for verification *)
  List.iter (fun (pm : Core_match.t) ->
    let start_line = pm.range_loc |> fst |> fun loc -> loc.pos.Pos.line in
    print_endline (Printf.sprintf "    Match at line %d" start_line)
  ) !matches;

  print_endline "Python in-memory scan: OK"

(*****************************************************************************)
(* Test: JavaScript in-memory scanning with pattern matching *)
(*****************************************************************************)

let test_javascript_in_memory_scan () =
  (* JavaScript code with eval() usage to detect *)
  let content = {|
function processUserInput(input) {
    eval(input);  // Dangerous: code injection risk
}

function anotherRisky(code) {
    eval(code);  // Another match
}

function safeFunction() {
    console.log("Hello, World!");
}
|} in
  let file = Fpath.v "test.js" in
  let lang = Lang.Js in

  (* Step 1: Parse the code from string *)
  let parse_result = Parse_target.just_parse_with_lang_from_string lang file content in
  assert (parse_result.ast <> []);
  assert (parse_result.errors = []);
  print_endline "  Step 1: Parsing succeeded";

  (* Step 2: Parse a pattern - detect calls to eval() *)
  let pattern_string = "eval($CODE)" in
  let pattern =
    match Parse_pattern.parse_pattern lang pattern_string with
    | Ok pat -> pat
    | Error msg -> failwith (Printf.sprintf "Failed to parse pattern: %s" msg)
  in
  print_endline "  Step 2: Pattern parsing succeeded";

  (* Step 3: Create a mini-rule for matching *)
  let rule = Mini_rule.{
    id = Rule_ID.of_string_exn "detect-eval";
    pattern;
    inside = false;
    message = "Use of eval() detected - potential code injection";
    metadata = None;
    severity = `Error;
    langs = [ lang ];
    pattern_string;
    fix = None;
    fix_regexp = None;
  } in
  print_endline "  Step 3: Mini-rule created";

  (* Step 4: Run pattern matching against the AST *)
  let matches = ref [] in
  let _results = Match_patterns.check
    ~hook:(fun pm -> matches := pm :: !matches)
    Rule_options.default
    [ rule ]
    (file, Origin.In_memory { name = Fpath.to_string file; content }, lang, parse_result.ast)
  in
  print_endline (Printf.sprintf "  Step 4: Pattern matching complete, found %d matches" (List.length !matches));

  (* Step 5: Verify we found the expected matches *)
  (* We expect 2 matches: one for each eval() call *)
  assert (List.length !matches = 2);

  (* Print match locations for verification *)
  List.iter (fun (pm : Core_match.t) ->
    let start_line = pm.range_loc |> fst |> fun loc -> loc.pos.Pos.line in
    print_endline (Printf.sprintf "    Match at line %d" start_line)
  ) !matches;

  print_endline "JavaScript in-memory scan: OK"

(*****************************************************************************)
(* All tests *)
(*****************************************************************************)

let tests () =
  Testo.categorize "In-memory scanning"
    [
      t "C++ in-memory scan" test_cpp_in_memory_scan;
      t "Python in-memory scan" test_python_in_memory_scan;
      t "JavaScript in-memory scan" test_javascript_in_memory_scan;
    ]
