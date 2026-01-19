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
(* Unit tests demonstrating and exercising in-memory parsing capabilities.
 *
 * This module tests the ability to parse code from strings (in-memory content)
 * rather than from files on disk. This is useful for:
 * - API/service integrations where content comes from HTTP requests
 * - Programmatic batch scanning of code snippets
 * - Editor/IDE integrations with unsaved buffers
 * - Testing without creating temporary files
 *)

let t = Testo.create

(*****************************************************************************)
(* Test: Basic string parsing for various languages *)
(*****************************************************************************)

(* Test parsing Python code from a string *)
let test_parse_python_string () =
  let content = {|
def hello():
    print("Hello, World!")

def add(a, b):
    return a + b
|} in
  let file = Fpath.v "test.py" in
  let result = Parse_target.just_parse_with_lang_from_string Lang.Python file content in
  (* Verify we got a non-empty AST with no errors *)
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "Python string parsing: OK"

(* Test parsing JavaScript code from a string *)
let test_parse_javascript_string () =
  let content = {|
function greet(name) {
    console.log(`Hello, ${name}!`);
}

const add = (a, b) => a + b;
|} in
  let file = Fpath.v "test.js" in
  let result = Parse_target.just_parse_with_lang_from_string Lang.Js file content in
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "JavaScript string parsing: OK"

(* Test parsing Go code from a string *)
let test_parse_go_string () =
  let content = {|
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}

func add(a, b int) int {
    return a + b
}
|} in
  let file = Fpath.v "test.go" in
  let result = Parse_target.just_parse_with_lang_from_string Lang.Go file content in
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "Go string parsing: OK"

(* Test parsing Java code from a string *)
let test_parse_java_string () =
  let content = {|
public class Hello {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }

    public static int add(int a, int b) {
        return a + b;
    }
}
|} in
  let file = Fpath.v "Hello.java" in
  let result = Parse_target.just_parse_with_lang_from_string Lang.Java file content in
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "Java string parsing: OK"

(* Test parsing Ruby code from a string *)
let test_parse_ruby_string () =
  let content = {|
def hello
  puts "Hello, World!"
end

def add(a, b)
  a + b
end
|} in
  let file = Fpath.v "test.rb" in
  let result = Parse_target.just_parse_with_lang_from_string Lang.Ruby file content in
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "Ruby string parsing: OK"

(* Test parsing Rust code from a string *)
let test_parse_rust_string () =
  let content = {|
fn main() {
    println!("Hello, World!");
}

fn add(a: i32, b: i32) -> i32 {
    a + b
}
|} in
  let file = Fpath.v "test.rs" in
  let result = Parse_target.just_parse_with_lang_from_string Lang.Rust file content in
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "Rust string parsing: OK"

(* Test parsing C++ code from a string *)
let test_parse_cpp_string () =
  let content = {|
#include <iostream>
#include <vector>
#include <string>

template<typename T>
class Container {
private:
    std::vector<T> items;

public:
    void add(const T& item) {
        items.push_back(item);
    }

    size_t size() const {
        return items.size();
    }

    T& operator[](size_t index) {
        return items[index];
    }
};

class Person {
private:
    std::string name;
    int age;

public:
    Person(const std::string& n, int a) : name(n), age(a) {}

    std::string getName() const { return name; }
    int getAge() const { return age; }

    void greet() const {
        std::cout << "Hello, I'm " << name << std::endl;
    }
};

int add(int a, int b) {
    return a + b;
}

int main() {
    Container<int> numbers;
    numbers.add(1);
    numbers.add(2);
    numbers.add(3);

    Person alice("Alice", 30);
    alice.greet();

    auto result = add(10, 20);
    std::cout << "Result: " << result << std::endl;

    return 0;
}
|} in
  let file = Fpath.v "test.cpp" in
  let result = Parse_target.just_parse_with_lang_from_string Lang.Cpp file content in
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "C++ string parsing: OK"

(*****************************************************************************)
(* Test: Creating in-memory targets *)
(*****************************************************************************)

(* Demonstrate creating an in-memory target for scanning *)
let test_create_in_memory_target () =
  let content = {|
def dangerous():
    eval(input())  # This should be flagged by security rules
|} in
  let name = "security_test.py" in
  let analyzer = Analyzer.of_lang Lang.Python in
  let target = Target.mk_in_memory_target ~name ~content analyzer in

  (* Verify the target was created correctly *)
  let origin = Target.origin target in
  (match origin with
   | Origin.In_memory { name = n; content = c } ->
       assert (n = name);
       assert (c = content);
       print_endline "In-memory target creation: OK"
   | _ ->
       failwith "Expected In_memory origin");
  ()

(*****************************************************************************)
(* Test: Parsing with name resolution *)
(*****************************************************************************)

let test_parse_and_resolve_names_from_string () =
  let content = {|
x = 1
y = x + 2
print(y)
|} in
  let file = Fpath.v "test.py" in
  let result = Parse_target.parse_and_resolve_name_from_string Lang.Python file content in
  assert (result.ast <> []);
  assert (result.errors = []);
  print_endline "Parse and resolve names from string: OK"

(*****************************************************************************)
(* Test: Multiple languages *)
(*****************************************************************************)

let test_multiple_languages () =
  let test_cases = [
    (Lang.Python, "test.py", "x = 1\nprint(x)");
    (Lang.Js, "test.js", "const x = 1;\nconsole.log(x);");
    (Lang.Go, "test.go", "package main\nfunc main() {}");
    (Lang.Ruby, "test.rb", "x = 1\nputs x");
    (Lang.Bash, "test.sh", "echo 'hello'\nls -la");
    (Lang.C, "test.c", "int main() { return 0; }");
    (Lang.Cpp, "test.cpp", "int main() { return 0; }");
    (Lang.Rust, "test.rs", "fn main() {}");
    (Lang.Kotlin, "test.kt", "fun main() {}");
    (Lang.Swift, "test.swift", "func main() {}");
  ] in
  List.iter (fun (lang, filename, content) ->
    let file = Fpath.v filename in
    let result = Parse_target.just_parse_with_lang_from_string lang file content in
    if result.errors <> [] then
      failwith (Printf.sprintf "Failed to parse %s: %s"
        filename (Parsing_result2.format_errors result.errors));
    print_endline (Printf.sprintf "%s parsing from string: OK" (Lang.show lang))
  ) test_cases

(*****************************************************************************)
(* All tests *)
(*****************************************************************************)

let tests () =
  Testo.categorize "In-memory parsing"
    [
      t "Python string parsing" test_parse_python_string;
      t "JavaScript string parsing" test_parse_javascript_string;
      t "Go string parsing" test_parse_go_string;
      t "Java string parsing" test_parse_java_string;
      t "Ruby string parsing" test_parse_ruby_string;
      t "Rust string parsing" test_parse_rust_string;
      t "C++ string parsing" test_parse_cpp_string;
      t "Create in-memory target" test_create_in_memory_target;
      t "Parse and resolve names from string" test_parse_and_resolve_names_from_string;
      t "Multiple languages" test_multiple_languages;
    ]
