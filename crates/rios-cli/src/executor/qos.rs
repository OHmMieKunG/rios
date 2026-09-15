//! MQC command execution over structured device APIs; packet queues remain in the owning lab.
use super::*;
pub(super) fn valid(command: &QosCommand, mode: CliMode) -> bool {
    use CliMode::*;
    match command {
        QosCommand::EnterClass { .. }
        | QosCommand::RemoveClass(_)
        | QosCommand::EnterPolicy(_)
        | QosCommand::RemovePolicy(_) => mode == GlobalConfiguration,
        QosCommand::Dscp(_) | QosCommand::Precedence(_) | QosCommand::MatchAcl { .. } => {
            matches!(mode, QosClassConfiguration(_))
        }
        QosCommand::EnterPolicyClass(_) | QosCommand::RemovePolicyClass(_) => matches!(
            mode,
            QosPolicyConfiguration(_) | QosPolicyClassConfiguration(..)
        ),
        QosCommand::Bandwidth(_)
        | QosCommand::Priority(_)
        | QosCommand::Police(_)
        | QosCommand::Shape(_) => matches!(mode, QosPolicyClassConfiguration(..)),
        QosCommand::BindOutput { .. } => matches!(
            mode,
            InterfaceConfiguration(_) | InterfaceRangeConfiguration(..)
        ),
        QosCommand::ShowInterface(_) => matches!(mode, UserExec | PrivilegedExec),
    }
}
pub(super) fn execute(
    device: &mut Device,
    session: &mut CliSession,
    command: QosCommand,
) -> Result<Execution, CliError> {
    use CliMode::*;
    let mut result = Execution::default();
    let removing_class = matches!(command, QosCommand::RemovePolicyClass(_));
    match command {
        QosCommand::EnterClass { name, match_all } => {
            session.mode = QosClassConfiguration(device.ensure_qos_class(&name, match_all)?)
        }
        QosCommand::RemoveClass(name) => device.remove_qos_class(&name)?,
        command @ (QosCommand::Dscp(_)
        | QosCommand::Precedence(_)
        | QosCommand::MatchAcl { .. }) => {
            let QosClassConfiguration(id) = session.mode else {
                return Err(CliError::WrongMode);
            };
            let mut class = device
                .running_config()
                .qos
                .classes
                .get(&id)
                .cloned()
                .ok_or(DeviceError::InvalidQosConfig)?;
            match command {
                QosCommand::Dscp(values) => class.dscp = values,
                QosCommand::Precedence(values) => class.precedence = values,
                QosCommand::MatchAcl { name, present } => {
                    if present {
                        class.access_lists.insert(name);
                    } else {
                        class.access_lists.remove(&name);
                    }
                }
                _ => {}
            }
            device.set_qos_class(id, class)?;
        }
        QosCommand::EnterPolicy(name) => {
            session.mode = QosPolicyConfiguration(device.ensure_qos_policy(&name)?)
        }
        QosCommand::RemovePolicy(name) => device.remove_qos_policy(&name)?,
        QosCommand::EnterPolicyClass(name) | QosCommand::RemovePolicyClass(name) => {
            let (QosPolicyConfiguration(id) | QosPolicyClassConfiguration(id, _)) = session.mode
            else {
                return Err(CliError::WrongMode);
            };
            if removing_class {
                device.remove_qos_policy_class(id, &name)?;
                session.mode = QosPolicyConfiguration(id);
            } else {
                session.mode =
                    QosPolicyClassConfiguration(id, device.ensure_qos_policy_class(id, &name)?);
            }
        }
        command @ (QosCommand::Bandwidth(_)
        | QosCommand::Priority(_)
        | QosCommand::Police(_)
        | QosCommand::Shape(_)) => {
            let QosPolicyClassConfiguration(id, class) = session.mode else {
                return Err(CliError::WrongMode);
            };
            let mut policy = device
                .running_config()
                .qos
                .policies
                .get(&id)
                .and_then(|p| p.classes.iter().find(|c| c.class == class))
                .cloned()
                .ok_or(DeviceError::InvalidQosConfig)?;
            match command {
                QosCommand::Bandwidth(rate) => policy.bandwidth_kbps = rate,
                QosCommand::Priority(rate) => policy.priority = rate,
                QosCommand::Police(rate) => policy.police = rate,
                QosCommand::Shape(rate) => policy.shape = rate,
                _ => {}
            }
            device.set_qos_policy_class(id, policy)?;
        }
        QosCommand::BindOutput { name, present } => {
            let id = device
                .running_config()
                .qos
                .policies
                .iter()
                .find_map(|(id, p)| (p.name == name).then_some(*id))
                .ok_or(DeviceError::InvalidQosConfig)?;
            edit_interfaces(device, session.mode, |d, interface| {
                if present {
                    d.set_service_policy_output(interface, Some(id))
                } else if d.running_config().interfaces[&interface].service_policy_output
                    == Some(id)
                {
                    d.set_service_policy_output(interface, None)
                } else {
                    Ok(())
                }
            })?;
        }
        QosCommand::ShowInterface(name) => {
            let interface = name
                .map(|name| {
                    device
                        .find_interface(&name)
                        .ok_or(DeviceError::InvalidInterface(name))
                })
                .transpose()?;
            result.request = Some(SimulationRequest::ShowPolicyInterface(interface));
        }
    }
    Ok(result)
}
