#include "wiremark/logger.hpp"

#include "wiremark/crypto.hpp"

#include <iomanip>
#include <sstream>

namespace wiremark {

std::string json_escape(const std::string& input) {
  std::ostringstream out;
  for (char c : input) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          std::ostringstream esc;
          esc << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(static_cast<unsigned char>(c));
          out << esc.str();
        } else {
          out << c;
        }
    }
  }
  return out.str();
}

Logger::Logger(const std::filesystem::path& dir, const std::string& session_name) : dir_(dir) {
  std::filesystem::create_directories(dir_);
  packet_log_path_ = dir_ / (session_name + ".packets.jsonl");
  summary_path_ = dir_ / (session_name + ".summary.json");
  packet_log_.open(packet_log_path_, std::ios::out | std::ios::app);
  require(packet_log_.good(), "cannot open packet log: " + packet_log_path_.string());
}

void Logger::write_json_line(const std::string& line) {
  packet_log_ << line << '\n';
  packet_log_.flush();
}

void Logger::sent(const Metadata& m) {
  stats_.sent++;
  stats_.bytes_sent += m.packet_length;
  std::ostringstream os;
  os << "{\"event\":\"sent\",\"seq\":" << m.sequence << ",\"send_ms\":" << m.send_ms
     << ",\"packet_sha256\":\"" << hex(m.sha) << "\",\"source_device\":\"" << json_escape(m.source_device)
     << "\",\"src_ip\":\"" << json_escape(m.source_ip) << "\",\"dst_ip\":\"" << json_escape(m.destination_ip)
     << "\",\"dst_port\":" << m.destination_port << ",\"ip_proto\":" << static_cast<int>(m.ip_protocol)
     << ",\"packet_len\":" << m.packet_length << "}";
  write_json_line(os.str());
}

void Logger::received(const Metadata& m,
                      std::uint64_t receive_ms,
                      bool verify_ok,
                      const std::string& verify_kind,
                      bool same_sha_seen_before) {
  stats_.received++;
  stats_.bytes_received += m.packet_length;
  if (verify_ok) stats_.verified++;
  if (!verify_ok) stats_.failed++;
  stats_.received_sequences[m.sequence] = verify_ok;
  const auto latency = m.send_ms != 0 && receive_ms >= m.send_ms ? receive_ms - m.send_ms : 0;
  std::ostringstream os;
  os << "{\"event\":\"received\",\"seq\":" << m.sequence << ",\"send_ms\":" << m.send_ms
     << ",\"receive_ms\":" << receive_ms << ",\"one_way_ms\":" << latency << ",\"verify_ok\":"
     << (verify_ok ? "true" : "false") << ",\"verify_kind\":\"" << json_escape(verify_kind)
     << "\",\"packet_sha256\":\"" << hex(m.sha) << "\",\"same_sha_seen_before\":"
     << (same_sha_seen_before ? "true" : "false") << ",\"source_device\":\""
     << json_escape(m.source_device) << "\",\"dst_ip\":\"" << json_escape(m.destination_ip)
     << "\",\"src_ip\":\"" << json_escape(m.source_ip) << "\",\"dst_port\":" << m.destination_port
     << ",\"ip_proto\":" << static_cast<int>(m.ip_protocol) << ",\"packet_len\":" << m.packet_length << "}";
  write_json_line(os.str());
}

void Logger::event(const std::string& name, const std::string& detail) {
  write_json_line("{\"event\":\"" + json_escape(name) + "\",\"ms\":" + std::to_string(now_ms()) +
                  ",\"detail\":\"" + json_escape(detail) + "\"}");
}

void Logger::capture(const CaptureRecord& r) {
  std::ostringstream os;
  os << "{\"event\":\"capture\",\"ms\":" << r.ms << ",\"direction\":\"" << json_escape(r.direction)
     << "\",\"src_ip\":\"" << json_escape(r.src_ip) << "\",\"dst_ip\":\"" << json_escape(r.dst_ip)
     << "\",\"src_port\":" << r.src_port << ",\"dst_port\":" << r.dst_port << ",\"packet_len\":"
     << r.length << ",\"packet_sha256\":\"" << r.sha256_hex << "\"}";
  write_json_line(os.str());
}

void Logger::decision(const DecisionRecord& r) {
  if (r.verdict == "accepted") stats_.accepted++;
  else if (r.verdict == "verify_failed") stats_.verify_failed++;
  else if (r.verdict == "duplicate_sequence" || r.verdict == "replayed_wrapper") stats_.duplicate_sequence++;
  if (!r.quarantine_manifest.empty()) stats_.quarantined++;
  std::ostringstream os;
  os << "{\"event\":\"packet_decision\",\"ms\":" << r.ms << ",\"seq\":" << r.sequence
     << ",\"verdict\":\"" << json_escape(r.verdict) << "\",\"action\":\""
     << json_escape(r.action) << "\",\"policy\":\"" << json_escape(r.policy) << "\",\"origin\":\""
     << json_escape(r.origin) << "\",\"verify_ok\":" << (r.verify_ok ? "true" : "false")
     << ",\"verify_kind\":\"" << json_escape(r.verify_kind) << "\",\"duplicate_sequence\":"
     << (r.duplicate_sequence ? "true" : "false") << ",\"same_sha_seen_before\":"
     << (r.same_sha_seen_before ? "true" : "false") << ",\"packet_sha256\":\""
     << json_escape(r.packet_sha256_hex) << "\",\"quarantine_manifest\":\""
     << json_escape(r.quarantine_manifest) << "\"}";
  write_json_line(os.str());
}

void Logger::write_summary(std::uint64_t round_start_ms, std::uint64_t round_end_ms) {
  std::ofstream out(summary_path_);
  require(out.good(), "cannot open summary log: " + summary_path_.string());
  const std::uint64_t missing_lower_bound =
      stats_.sent > stats_.received_sequences.size() ? stats_.sent - stats_.received_sequences.size() : 0;
  out << "{\n"
      << "  \"round_start_ms\": " << round_start_ms << ",\n"
      << "  \"round_end_ms\": " << round_end_ms << ",\n"
      << "  \"sent\": " << stats_.sent << ",\n"
      << "  \"received\": " << stats_.received << ",\n"
      << "  \"verified\": " << stats_.verified << ",\n"
      << "  \"failed\": " << stats_.failed << ",\n"
      << "  \"accepted\": " << stats_.accepted << ",\n"
      << "  \"verify_failed\": " << stats_.verify_failed << ",\n"
      << "  \"duplicate_sequence\": " << stats_.duplicate_sequence << ",\n"
      << "  \"quarantined\": " << stats_.quarantined << ",\n"
      << "  \"local_missing_lower_bound\": " << missing_lower_bound << ",\n"
      << "  \"bytes_sent\": " << stats_.bytes_sent << ",\n"
      << "  \"bytes_received\": " << stats_.bytes_received << "\n"
      << "}\n";
}

}  // namespace wiremark
