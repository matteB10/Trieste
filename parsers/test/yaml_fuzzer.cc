#include "trieste/logging.h"

#include <CLI/CLI.hpp>
#include <filesystem>
#include <trieste/fuzzer.h>
#include <trieste/yaml.h>

using namespace trieste;

int process_file(
  const std::filesystem::path& bin,
  const std::filesystem::path& file,
  Reader& reader,
  std::string& test_start_pass,
  Node& sample_program,
  std::map<Token, std::vector<Node>>& sample_trees)
{
  // Treat regular files and symlinks as files. Skip directories.
  if (
    !std::filesystem::is_regular_file(file) &&
    !std::filesystem::is_symlink(file))
  {
    logging::Debug() << "Unable to read sample file " << file << std::endl;
    return 1;
  }
  // Only process files with the expected extensions.
  auto ext = file.extension().string();
  auto file_ending = "." + reader.language_name();
  if (ext != ".trieste" && ext != file_ending)
  {
    logging::Debug() << "Unexpected file ending " << ext << " in file " << file
                     << std::endl;
    return 1;
  }

  if (ext == ".trieste")
  {
    auto source = SourceDef::load(file);
    auto view = source->view();
    auto pos = std::min(view.find_first_of('\n'), view.size());
    auto pos2 = std::min(view.find_first_of('\n', pos + 1), view.size());
    auto pass = view.substr(pos + 1, pos2 - pos - 1);

    if (view.compare(0, pos, reader.language_name()) != 0)
    {
      logging::Debug() << "File " << file
                       << " does not start with the language name \""
                       << reader.language_name() << "\"" << std::endl;
    }

    test_start_pass = reader.start_pass(pass).offset(pos2 + 1).start_pass();
  }
  else
  {
    auto prev_pass = reader.pass_index(test_start_pass) == 0 ?
      reader.pass_names().front() :
      reader.pass_names().at(reader.pass_index(test_start_pass) - 1);
    // if (reader.pass_index(test_start_pass) == 0)
    // {
    //   //sample_program = reader.parser().parse(file); // Run parser only
    //   //reader.end_pass("parse");
    //   prev_pass = reader.pass_names().front(); // Start testing from the
    //   first pass if start_pass is not set by file
    // }
    // else
    // {

    //   // Get the pass prior to the desired start pass
    //   std::cout << "Testing from pass " << reader.pass_index(test_start_pass)
    //   << " for file " << file
    //             << std::endl;
    //   auto prev_pass =
    //     reader.pass_names().at(reader.pass_index(test_start_pass) - 1);
    // }
    reader.executable(bin)
      .file(file)
      .wf_check_enabled(true)
      .debug_enabled(false)
      .end_pass(prev_pass);

    auto result = reader.read();
    std::cout << "Finished processing file " << file << " with result: "
              << (result.ok ? "OK" : "FAIL") << std::endl;

    if (!result.ok)
    {
      logging::Error err;
      result.print_errors(err);
      return 1;
    }
    sample_program = result.ast; // Parse file as test program
  }

  if (!sample_program)
  {
    logging::Error() << "Failed to parse test program from " << file
                     << std::endl;
    return 1;
  }
  sample_program->traverse([&](auto& n) {
    if (n != Error)
      sample_trees[n->type()].push_back(n);
    return true;
  });

  return 0;
}

int main(int argc, char** argv)
{
  CLI::App app;

  app.set_help_all_flag("--help-all", "Expand all help");

  std::string transform;
  app.add_option("transform", transform, "Transform to test")
    ->check(CLI::IsMember({"reader", "writer", "event_writer", "to_json"}))
    ->required(true);

  uint32_t seed = std::random_device()();
  app.add_option("-s,--seed", seed, "Random seed");

  uint32_t count = 100;
  app.add_option("-c,--count", count, "Number of seed to test");

  bool failfast = false;
  app.add_flag("-f,--failfast", failfast, "Stop on first failure");

  std::string log_level;
  app
    .add_option(
      "-l,--log_level",
      log_level,
      "Set Log Level to one of "
      "Trace, Debug, Info, "
      "Warning, Output, Error, "
      "None")
    ->check(logging::set_log_level_from_string);

  // Sampling options
  std::filesystem::path sample_files;
  app.add_option(
    "--samples",
    sample_files,
    "Files to extract sample nodes from for fuzz testing");

  size_t sampling_level = 1;
  app.add_option(
    "--sampling-level",
    sampling_level,
    "Level of sampling to use for selecting sample nodes");

  size_t sampling_frequency = 50; // Default to 50% sampling frequency
  app.add_option(
    "--sampling-frequency",
    sampling_frequency,
    "Frequency of using sampled nodes over randomly generated nodes during "
    "testing (0-100)");

  auto bound_vars = true;
  app.add_option(
    "--gen_bound", bound_vars, "Generate bound variable names if possible");

  try
  {
    app.parse(argc, argv);
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }

  logging::Output() << "Testing x" << count << ", seed: " << seed << std::endl;

  Fuzzer fuzzer;
  Reader reader = yaml::reader();
  std::string test_start_pass =
    reader.pass_names().front(); // Default to first pass if not set by file
  std::cout << "Testing from pass " << test_start_pass << std::endl;
  if (transform == "reader")
  {
    fuzzer = Fuzzer(reader);
  }
  else if (transform == "writer")
  {
    auto writer = yaml::writer("fuzzer");
    fuzzer = Fuzzer(writer, reader.parser().generators());
    test_start_pass =
      writer.passes()
        .front()
        ->name(); // Start testing from the first pass of the writer
  }
  else if (transform == "event_writer")
  {
    auto event_writer = yaml::event_writer("fuzzer");
    fuzzer = Fuzzer(event_writer, reader.parser().generators());
    test_start_pass =
      event_writer.passes()
        .front()
        ->name(); // Start testing from the first pass of the event writer
  }
  else if (transform == "to_json")
  {
    fuzzer = Fuzzer(yaml::to_json(), reader.parser().generators());
  }

  // Configure fuzzer with sampling options
  bool sampling_enabled = false;
  std::map<Token, std::vector<Node>> sample_trees;
  Node sample_program;
  std::filesystem::path bin_path;

  try
  {
    bin_path = std::filesystem::canonical(argv[0]);
  }
  catch (const std::filesystem::filesystem_error& e)
  {
    bin_path = std::filesystem::absolute(argv[0]);
  }

  if (!sample_files.empty() && std::filesystem::exists(sample_files))
  {
    // Extract sample nodes from files
    if (std::filesystem::is_directory(sample_files))
    {
      // Process all YAML files in directory
      for (const auto& entry :
           std::filesystem::recursive_directory_iterator(sample_files))
      {
        if (entry.is_regular_file())
        {
          process_file(
            bin_path,
            entry.path(),
            reader,
            test_start_pass,
            sample_program,
            sample_trees);
        }
      }
    }
    else
    {
      // Process single file
      process_file(
        bin_path,
        sample_files,
        reader,
        test_start_pass,
        sample_program,
        sample_trees);
    }
    sampling_enabled = !sample_trees.empty();
    std::cout << "Extracted " << sample_trees.size()
              << " sample nodes for fuzz testing" << std::endl;
  }

  fuzzer.start_seed(seed)
    .seed_count(count)
    .failfast(failfast)
    .sampling_level(sampling_level)
    .sampling_enabled(sampling_enabled)
    .sampling_frequency(sampling_frequency)
    .sample_nodes(sample_trees)
    .bound_vars(bound_vars);

  if (sampling_enabled)
  {
    std::cout << "Running fuzzer with samples" << std::endl;
    return fuzzer.test_with_samples();
  }
  else
  {
    return fuzzer.test();
  }
}
