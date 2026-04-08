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
  bool parse_only,
  Node& sample_program,
  std::map<Token, std::vector<Node>>& sample_trees)
{
  auto end_pass = reader.passes().back()->name(); // Default to last pass if not set by file
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

    end_pass = reader.start_pass(pass).offset(pos2 + 1).start_pass();
  }
  else
  {
    end_pass = parse_only ? "parse" : reader.passes().back()->name();
    reader.executable(bin)
      .file(file)
      .wf_check_enabled(true)
      .debug_enabled(false)
      .end_pass(end_pass);

    auto result = reader.read();
    logging::Debug() << "Finished building samples from file " << file
                     << std::endl;

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
    logging::Debug() << "Failed to parse test program from " << file
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

void populate_samples(
  Reader& reader,
  char** argv,
  bool parse_only,
  std::map<Token, std::vector<Node>>& sample_trees,
  std::filesystem::path sample_files)
{
  // Configure fuzzer with sampling options
  Node sample_program;
  std::filesystem::path bin_path;
  int ret = 0;

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
          ret = process_file(
            bin_path,
            entry.path(),
            reader,
            parse_only,
            sample_program,
            sample_trees);
        }
      }
    }
    else
    {
      // Process single file
      ret = process_file(
        bin_path,
        sample_files,
        reader,
        parse_only,
        sample_program,
        sample_trees);
    }
    if (ret)
    {
      logging::Output() << "All files in " << sample_files
                        << " could not be processed" << std::endl;

    }
  }
  else
  {
    logging::Output() << "No sample files provided or file " << sample_files
                      << " does not exist" << std::endl;
  }
}

int main(int argc, char** argv)
{
  CLI::App app;

  app.set_help_all_flag("--help-all", "Expand all help");

  std::string transform;
  app.add_option("transform", transform, "Transform to test")
    ->check(
      CLI::IsMember(
        {"reader", "writer", "event_writer", "to_json", "reader_to_json"}))
    ->required(true);

  uint32_t seed = std::random_device()();
  app.add_option("-s,--seed", seed, "Random seed");

  uint32_t count = 100;
  app.add_option("-c,--count", count, "Number of seed to test");

  bool sequence = false;
  app.add_flag("--sequence", sequence, "Run passes in sequence");

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
  auto* samples_option =app.add_option(
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
  Reader reader_tojson = yaml::reader() >>= yaml::to_json();
  auto parse_only = false;
  std::map<Token, std::vector<Node>> sample_trees;

  if (transform == "reader")
  {
    fuzzer = Fuzzer(reader);
    parse_only = true; // Only run parser for reader
    populate_samples(reader, argv, parse_only, sample_trees, sample_files); 
  }
  else if (transform == "writer")
  {
    auto writer = yaml::writer("fuzzer");
    fuzzer = Fuzzer(writer, reader.parser().generators());
    populate_samples(reader, argv, parse_only, sample_trees, sample_files);
  }
  else if (transform == "event_writer")
  {
    auto event_writer = yaml::event_writer("fuzzer");
    fuzzer = Fuzzer(event_writer, reader.parser().generators());
    populate_samples(reader, argv, parse_only, sample_trees, sample_files); 
  }
  else if (transform == "to_json")
  {
    fuzzer = Fuzzer(yaml::to_json(), reader.parser().generators());
    populate_samples(reader, argv, parse_only, sample_trees, sample_files); 
  }
  else if (transform == "reader_to_json")
  {
    fuzzer = Fuzzer(reader_tojson);
    parse_only = true;
    populate_samples(reader_tojson, argv, parse_only, sample_trees, sample_files);
  }

  bool sampling_enabled = !sample_trees.empty();
  if (samples_option->count() > 0)
  {
    logging::Info() << "Extracted " << sample_trees.size()
                     << " sample nodes for fuzz testing" << std::endl;
  }

  return fuzzer.start_seed(seed)
    .seed_count(count)
    .failfast(failfast)
    .max_retries(count * 2)
    .test_sequence(sequence)
    .bound_vars(bound_vars)
    .sampling_level(sampling_level)
    .sampling_enabled(sampling_enabled)
    .sampling_frequency(sampling_frequency)
    .sample_nodes(sample_trees)
    .test();
}
