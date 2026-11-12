#include "totp_detection.h"
namespace ownvpn {
TotpDetection TotpParameterDetector::Observe(const TotpConfig& config, std::string_view code, int64_t now) {
    auto matches = FindTotpMatches(config, code, now);
    if (matches.empty()) {
        Reset();
        return {DetectionState::NoMatch, {}};
    }
    if (seed_ != config.secretBase32 || previous_.empty()) {
        Reset();
        seed_ = config.secretBase32;
        for (auto match : matches) {
            previous_.push_back({match, now / match.periodSeconds + match.windowOffset});
        }
        return {DetectionState::AwaitNextCode, std::move(matches)};
    }
    std::vector<Observation> survivors;
    bool sawSameWindow = false;
    for (auto match : matches) {
        for (const auto& previous : previous_) {
            if (match.algorithm != previous.match.algorithm ||
                match.periodSeconds != previous.match.periodSeconds) {
                continue;
            }
            auto counter = now / match.periodSeconds + match.windowOffset;
            if (counter <= previous.phoneCounter) {
                sawSameWindow = true;
            } else {
                survivors.push_back({match, counter});
            }
        }
    }
    if (sawSameWindow) {
        return {DetectionState::SameWindow, std::move(matches)};
    }
    if (survivors.empty()) {
        Reset();
        return {DetectionState::NoMatch, {}};
    }
    previous_ = std::move(survivors);
    std::vector<TotpMatch> confirmed;
    for (const auto& candidate : previous_) {
        confirmed.push_back(candidate.match);
    }
    return {confirmed.size() == 1 ? DetectionState::Confirmed : DetectionState::Ambiguous,
            std::move(confirmed)};
}
void TotpParameterDetector::Reset() {
    Wipe(seed_);
    previous_.clear();
}
} // namespace ownvpn
