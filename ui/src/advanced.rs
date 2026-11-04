use eframe::egui::{self, RichText, Ui};

use crate::theme;

const CREDIT: &str = "This Hypervisor was provided by .zhk_ on Discord";
const AMD_VENDOR: &str = "AuthenticAMD";
const INTEL_VENDOR: &str = "GenuineIntel";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Hypervisor {
    #[default]
    Idle,
    Unsupported(String),
    Confirming,
    NotBuilt,
}

#[cfg(target_arch = "x86_64")]
fn cpu_vendor() -> String {
    let info = std::arch::x86_64::__cpuid(0);
    let bytes: Vec<u8> = [info.ebx, info.edx, info.ecx]
        .iter()
        .flat_map(|part| part.to_le_bytes())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_vendor() -> String {
    String::new()
}

fn first_check(vendor: &str) -> Hypervisor {
    if vendor == AMD_VENDOR {
        return Hypervisor::Confirming;
    }

    let cpu = if vendor == INTEL_VENDOR {
        "This machine has an Intel CPU."
    } else {
        "This machine does not have an AMD CPU."
    };
    Hypervisor::Unsupported(format!(
        "The Euphoria Hypervisor only runs on AMD CPUs right now. {cpu}"
    ))
}

pub fn show(ui: &mut Ui, state: &mut Hypervisor) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(20, 18))
        .show(ui, |ui| {
            ui.label(RichText::new("Euphoria Hypervisor").size(18.0));
            ui.add_space(8.0);
            if ui.button("Start").clicked() {
                *state = first_check(&cpu_vendor());
            }
            ui.add_space(6.0);
            ui.label(RichText::new(CREDIT).size(11.5).color(theme::MUTED));

            if *state == Hypervisor::NotBuilt {
                ui.add_space(14.0);
                ui.label(
                    RichText::new(
                        "The hypervisor is not built yet, so nothing was started. \
                         Its code will go in the hypervisor folder.",
                    )
                    .color(theme::NUMBER),
                );
            }
        });

    let next = match state {
        Hypervisor::Unsupported(message) => {
            let message = message.clone();
            dialog(ui, "Not available on this CPU", &message, |ui| {
                ui.button("OK").clicked().then_some(Hypervisor::Idle)
            })
        }
        Hypervisor::Confirming => dialog(
            ui,
            "Are you sure you know what you are doing?",
            "A hypervisor runs underneath the operating system. A mistake at this level can \
             crash or freeze the whole machine.",
            |ui| {
                if ui.button("Yes, continue").clicked() {
                    Some(Hypervisor::NotBuilt)
                } else if ui.button("Cancel").clicked() {
                    Some(Hypervisor::Idle)
                } else {
                    None
                }
            },
        ),
        Hypervisor::Idle | Hypervisor::NotBuilt => None,
    };
    if let Some(next) = next {
        *state = next;
    }
}

fn dialog(
    ui: &Ui,
    title: &str,
    message: &str,
    buttons: impl FnOnce(&mut Ui) -> Option<Hypervisor>,
) -> Option<Hypervisor> {
    egui::Modal::new(egui::Id::unique("hypervisor_dialog"))
        .show(ui.ctx(), |ui| {
            ui.set_max_width(440.0);
            ui.label(RichText::new(title).size(16.0));
            ui.add_space(8.0);
            ui.label(message);
            ui.add_space(14.0);
            ui.horizontal(buttons).inner
        })
        .inner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amd_goes_to_the_confirmation() {
        assert_eq!(first_check("AuthenticAMD"), Hypervisor::Confirming);
    }

    #[test]
    fn intel_and_others_are_stopped_first() {
        let intel = first_check("GenuineIntel");
        assert!(matches!(&intel, Hypervisor::Unsupported(text) if text.contains("Intel CPU")));

        let other = first_check("");
        assert!(matches!(&other, Hypervisor::Unsupported(text) if text.contains("AMD")));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn reads_a_cpu_vendor() {
        assert_eq!(cpu_vendor().len(), 12);
    }
}
