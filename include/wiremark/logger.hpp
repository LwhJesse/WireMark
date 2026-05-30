#pragma once

#include "wiremark/protocol.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <string>

namespace wiremark {

struct LogStats {
  std::uint64_t sent{0};
  std::uint64_t received{0};
  std::uint64_t verified{0};
  std::uint64_t failed{0};
  std::uint64_t accepted{0};
  std::uint64_t verify_failed{0};
  std::uint64_t duplicate_sequence{0};
  std::uint64_t quarantined{0};
  std::uint64_t bytes_sent{0};
  std::uint64_t bytes_received{0};
  std::map<std::uint64_t, bool> received_sequences;
};

struct CaptureRecord {
  std::uint64_t ms{0};
  std::string direction;
  std::string src_ip;
  std::string dst_ip;
  std::uint16_t src_port{0};
  std::uint16_t dst_port{0};
  std::uint32_t length{0};
  std::string sha256_hex;
};

struct DecisionRecord {
  std::uint64_t ms{0};
  std::uint64_t sequence{0};
  std::string verdict;
  std::string action;
  std::string policy;
  std::string origin;
  bool verify_ok{false};
  std::string verify_kind{"tag12"};
  bool duplicate_sequence{false};
  bool same_sha_seen_before{false};
  std::string packet_sha256_hex;
  std::string quarantine_manifest;
};

class Logger {
 public:
  Logger(const std::filesystem::path& dir, const std::string& session_name);

  void sent(const Metadata& m);
  void received(const Metadata& m,
                std::uint64_t receive_ms,
                bool verify_ok,
                const std::string& verify_kind = "tag12",
                bool same_sha_seen_before = false);
  void event(const std::string& name, const std::string& detail);
  void capture(const CaptureRecord& r);
  void decision(const DecisionRecord& r);
  void write_summary(std::uint64_t round_start_ms, std::uint64_t round_end_ms);

  const std::filesystem::path& packet_log_path() const { return packet_log_path_; }
  const std::filesystem::path& summary_path() const { return summary_path_; }
  const LogStats& stats() const { return stats_; }

 private:
  void write_json_line(const std::string& line);

  std::filesystem::path dir_;
  std::filesystem::path packet_log_path_;
  std::filesystem::path summary_path_;
  std::ofstream packet_log_;
  LogStats stats_;
};

std::string json_escape(const std::string& input);

}  // namespace wiremark
