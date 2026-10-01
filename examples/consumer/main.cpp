// Downstream consumer of the installed Incident State Fabric package.
//
// It links only against the installed artifact and the public headers, and it
// exercises the parts of the contract a facility integration depends on:
// bootstrap, report, preview/commit agreement, a durable restart, and the
// refusal of a stale actor.

#include <cstdio>
#include <filesystem>
#include <string>

#include "isf/isf.h"

namespace {

int Fail(const std::string& message) {
  std::fprintf(stderr, "consumer: %s\n", message.c_str());
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path root =
      argc > 1 ? std::filesystem::path(argv[1]) : std::filesystem::temp_directory_path() / "isf-consumer";

  std::error_code error;
  std::filesystem::remove_all(root, error);

  isf::OpenOptions options;
  options.path = root.string();
  options.create_if_missing = true;

  auto opened = isf::IncidentFabric::Open(options);
  if (!opened.ok()) return Fail("open failed: " + opened.status().ToString());
  isf::IncidentFabricPtr fabric = std::move(opened).value();

  std::uint64_t key_counter = 0;
  const auto header = [&](isf::AuthorityId authority) {
    isf::MutationHeader header;
    header.actor.authority = authority;
    const auto status = fabric->GetStatus();
    header.actor.epoch = status.value().control_epoch;
    header.key = isf::IdempotencyKey{0xfeedfacecafebeefull, ++key_counter};
    return header;
  };

  isf::RegisterAuthorityRequest bootstrap;
  bootstrap.header.actor.authority = isf::AuthorityId{};
  const auto initial = fabric->GetStatus();
  if (!initial.ok()) return Fail("status failed");
  bootstrap.header.actor.epoch = initial.value().control_epoch;
  bootstrap.header.key = isf::IdempotencyKey{0xfeedfacecafebeefull, ++key_counter};
  bootstrap.name = "consumer-director";
  bootstrap.role = isf::AuthorityRole::FacilityDirector;
  bootstrap.rationale = "consumer bootstrap";
  auto receipt = fabric->RegisterAuthority(bootstrap);
  if (!receipt.ok()) return Fail("bootstrap failed: " + receipt.status().ToString());
  const isf::AuthorityId director = receipt.value().authority;

  isf::RegisterAuthorityRequest create;
  create.header = header(director);
  create.name = "consumer-operator";
  create.role = isf::AuthorityRole::Operator;
  create.rationale = "consumer bootstrap";
  receipt = fabric->RegisterAuthority(create);
  if (!receipt.ok()) return Fail("role creation failed");
  const isf::AuthorityId operator_role = receipt.value().authority;

  isf::ReportIncidentRequest report;
  report.header = header(operator_role);
  report.cls = isf::IncidentClass::Cooling;
  report.reported_severity = isf::Severity::Major;
  report.summary = "chiller 3 tripped on high condenser pressure";
  report.scope.objects.push_back(isf::ObjectRef{isf::ObjectKind::Chiller, "chiller-3"});
  report.scope.failure_domains.push_back(
      isf::FailureDomainRef{isf::FailureDomainKind::CoolingLoop, "loop-b"});
  report.source_system = "consumer-example";
  report.source_event_id = "evt-1";

  const auto preview = fabric->Preview(isf::AnyRequest{report});
  if (!preview.ok() || !preview.value().would_commit) {
    return Fail("preview refused a request the commit should accept");
  }
  const auto committed = fabric->ReportIncident(report);
  if (!committed.ok()) return Fail("report failed: " + committed.status().ToString());
  std::printf("reported incident %llu at generation %llu\n",
              static_cast<unsigned long long>(committed.value().incident.value()),
              static_cast<unsigned long long>(committed.value().generation.value()));

  // A stale actor, fenced by the control epoch.
  isf::ReportIncidentRequest stale = report;
  stale.header.key = isf::IdempotencyKey{0xfeedfacecafebeefull, ++key_counter};
  stale.header.actor.epoch = isf::ControlEpoch{initial.value().control_epoch.value + 99};
  const auto refused = fabric->ReportIncident(stale);
  if (refused.ok()) return Fail("a stale control epoch was accepted");
  std::printf("stale actor refused with %s\n", isf::ToString(refused.status().code()));

  if (!fabric->Close().ok()) return Fail("close failed");

  auto reopened = isf::IncidentFabric::Open(options);
  if (!reopened.ok()) return Fail("reopen failed: " + reopened.status().ToString());
  const auto view = reopened.value()->GetIncident(committed.value().incident);
  if (!view.ok()) return Fail("the incident did not survive the restart");
  std::printf("after restart: incident %llu is %s with severity %s at revision %llu\n",
              static_cast<unsigned long long>(view.value().id.value()),
              isf::ToString(view.value().state), isf::ToString(view.value().severity),
              static_cast<unsigned long long>(view.value().revision));
  if (!reopened.value()->Close().ok()) return Fail("second close failed");

  std::filesystem::remove_all(root, error);
  std::printf("consumer ok, library version %s\n", isf::VersionString());
  return 0;
}
