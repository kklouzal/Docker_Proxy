from services.exclusions_store import get_domain_exclusion_preset, list_domain_exclusion_presets


def test_domain_exclusion_presets_include_microsoft_update_store_baseline():
    presets = list_domain_exclusion_presets()
    keys = {preset.key for preset in presets}
    assert "microsoft_update_store" in keys

    preset = get_domain_exclusion_preset("microsoft_update_store")
    assert preset is not None
    assert preset.name == "Microsoft Windows Update + Store"
    assert "*.prod.do.dsp.mp.microsoft.com" in preset.domains
    assert "*.update.microsoft.com" in preset.domains
    assert "login.live.com" in preset.domains
    assert all(domain == domain.strip().lower() for domain in preset.domains)