#include "trieste/logging.h"

#include <CLI/CLI.hpp>
#include <filesystem>
#include <trieste/fuzzer.h>
#include <trieste/yaml.h>

using namespace trieste;

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

  Reader reader = yaml::reader();
  Reader reader_tojson = yaml::reader() >>= yaml::to_json();
  Nodes sample_trees;

  // Determine which reader to use for parsing sample files.
  Reader& sample_reader =
    (transform == "reader_to_json") ? reader_tojson : reader;

  if (!sample_files.empty() && std::filesystem::exists(sample_files))
  {
    if (std::filesystem::is_directory(sample_files))
    {
      for (const auto& entry :
           std::filesystem::recursive_directory_iterator(sample_files))
      {
        if (entry.is_regular_file() && entry.path().extension() == ".yaml")
        {
          Node sample_program = sample_reader.parser().parse(entry.path());
          if (sample_program)
            sample_trees.push_back(sample_program);
          else
            logging::Error() << "Failed to parse " << entry.path()
                             << std::endl;
        }
      }
    }
    else
    {
      Node sample_program = sample_reader.parser().parse(sample_files);
      if (!sample_program)
      {
        logging::Error() << "Failed to parse test program from " << sample_files
                         << std::endl;
        return 1;
      }
      sample_trees.push_back(sample_program);
    }
    logging::Info() << "Collected " << sample_trees.size()
                    << " sample trees for fuzz testing" << std::endl;
  }

  Fuzzer fuzzer;
  if (transform == "reader")
    fuzzer = Fuzzer(reader);
  else if (transform == "writer")
    fuzzer = Fuzzer(yaml::writer("fuzzer"), reader.parser().generators());
  else if (transform == "event_writer")
    fuzzer = Fuzzer(yaml::event_writer("fuzzer"), reader.parser().generators());
  else if (transform == "to_json")
    fuzzer = Fuzzer(yaml::to_json(), reader.parser().generators());
  else if (transform == "reader_to_json")
    fuzzer = Fuzzer(reader_tojson);

  return fuzzer.start_seed(seed)
    .seed_count(count)
    .failfast(failfast)
    .max_retries(count * 2)
    .test_sequence(sequence)
    .bound_vars(bound_vars)
    .sampling_level(sampling_level)
    .sampling_enabled(!sample_trees.empty())
    .sampling_frequency(sampling_frequency)
    .sample_trees(sample_trees)
    .test();
}
