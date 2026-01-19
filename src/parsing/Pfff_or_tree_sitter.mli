(*
   Copyright (c) 2023-2024 Semgrep Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   version 2.1 as published by the Free Software Foundation.

   This library is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
   LICENSE for more details.
*)
type 'ast parser =
  | Pfff of (Fpath.t -> 'ast * Parsing_stat.t)
  | TreeSitter of (Fpath.t -> ('ast, unit) Tree_sitter_run.Parsing_result.t)

(* TODO: factorize with previous type *)
type 'ast pattern_parser =
  | PfffPat of (string -> 'ast)
  | TreeSitterPat of (string -> ('ast, unit) Tree_sitter_run.Parsing_result.t)

(* Parser types for string/in-memory content.
   The string argument is the content, not a filename.
   The Fpath.t argument is a "virtual" path used for error reporting. *)
type 'ast str_parser =
  | PfffStr of (Fpath.t -> string -> 'ast * Parsing_stat.t)
  | TreeSitterStr of
      (Fpath.t -> string -> ('ast, unit) Tree_sitter_run.Parsing_result.t)

(* usage:
    run file [
        TreeSitter (Parse_typescript_tree_sitter.parse);
        Pfff (throw_tokens Parse_js.parse);
     ] Js_to_generic.program
*)
val run :
  Fpath.t ->
  'ast parser list ->
  ('ast -> AST_generic.program) ->
  Parsing_result2.t

(* Like [run] but parses from a string instead of a file.
   The Fpath.t argument is a "virtual" path used for error reporting/token locations.
   usage:
    run_from_string (Fpath.v "test.py") content [
        TreeSitterStr (fun file content ->
          Parse_python_tree_sitter.parse_string ~file:(Fpath.to_string file) ~contents:content);
     ] Python_to_generic.program
*)
val run_from_string :
  Fpath.t ->
  string ->
  'ast str_parser list ->
  ('ast -> AST_generic.program) ->
  Parsing_result2.t

(* usage:
    let js_ast =
      str |> run_pattern [
         PfffPat Parse_js.any_of_string;
         TreeSitterPat Parse_typescript_tree_sitter.parse_pattern;
         ]
      in
      Js_to_generic.any js_ast
*)
val run_pattern : 'ast pattern_parser list -> string -> 'ast

(* helpers used both in Parse_target.ml and Parse_target2.ml *)

val exn_of_loc : Tok.location -> Exception.t

(* used by Parse_jsonnet *)
val error_of_tree_sitter_error :
  Tree_sitter_run.Tree_sitter_error.t -> Exception.t

val throw_tokens :
  (Fpath.t -> ('ast, 'toks) Parsing_result.t) ->
  Fpath.t ->
  'ast * Parsing_stat.t

val run_external_parser :
  Fpath.t ->
  (Fpath.t -> (AST_generic.program, unit) Tree_sitter_run.Parsing_result.t) ->
  Parsing_result2.t

(* helpers used both in Parse_pattern.ml and Parse_pattern2.ml *)

val extract_pattern_from_tree_sitter_result :
  ('any, unit) Tree_sitter_run.Parsing_result.t -> 'any

val dump_and_print_errors :
  ('a -> unit) -> ('a, 'extra) Tree_sitter_run.Parsing_result.t -> unit
