import json
import logging
import os
import re
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import boto3
    from botocore.config import Config as BotoConfig
except ModuleNotFoundError:  # pragma: no cover - local tests can run without AWS SDK
    boto3 = None
    BotoConfig = None


LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

MAX_CONNECTION_STATUS_IDS = 25
MAX_REGION_SCAN_WORKERS = 4
MAX_TAG_LOOKUP_WORKERS = 4
# Total API attempts (initial call + retries). The scan bursts concurrent
# describe calls across regions and tag-lookup workers, so throttling is
# expected on large fleets; adaptive mode adds client-side rate limiting on
# top of the standard retry behavior. Completeness matters more than latency
# here, and the Lambda timeout leaves ample room for backoff.
MAX_API_ATTEMPTS = 8
CONNECTED_STATE = "CONNECTED"
MAX_NETWORK_INTERFACE_FILTER_VALUES = 100
# The percentage circuit breaker only applies to fleets of at least this size;
# tiny fleets make percentages meaningless (1 of 2 candidates = 50%).
MIN_EVALUATED_FOR_PERCENT_CHECK = 10
WORKSPACES_ENI_DESCRIPTION_FRAGMENT = "created by amazon workspaces for aws account id"
WORKSPACES_ENI_DESCRIPTION_FILTERS = (
    "Created By Amazon Workspaces for AWS Account ID*",
    "Created By Amazon WorkSpaces for AWS Account ID*",
)
SKIP_AUTO_DELETE_TAG_KEY = "Skip_AutoDelete"
TERMINATABLE_STATES = {"AVAILABLE", "STOPPED", "ERROR", "UNHEALTHY", "IMPAIRED"}
CONFIG_VALIDATION_RESOURCE_TYPE = "Custom::WorkSpacesLifecycleConfigValidation"
CONFIG_VALIDATION_PHYSICAL_RESOURCE_ID = "WorkSpacesLifecycleConfigValidation"
# Upper bound for the pre-signed S3 PUT that answers a CloudFormation custom
# resource event; without it a stalled PUT blocks until the Lambda timeout.
CFN_RESPONSE_TIMEOUT_SECONDS = 30
REGION_NAME_PATTERN = re.compile(r"^[a-z]{2,8}(?:-[a-z0-9]+)+-[0-9]+$")
ARN_PARTITION_PATTERN = re.compile(r"^[a-z0-9-]+$")
AWS_ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
SNS_TOPIC_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
REPORT_SUBJECT = "WorkSpaces Lifecycle Manager Report"


@dataclass(frozen=True)
class Config:
    sns_topic_arn: str
    warn_after_days: int = 30
    terminate_after_days: int = 60
    auto_terminate: bool = False
    target_regions: Tuple[str, ...] = ()
    max_termination_percent: int = 50
    max_unknown_percent: int = 10

    @classmethod
    def from_env(cls) -> "Config":
        sns_topic_arn = os.environ["SNS_TOPIC_ARN"]
        warn_after_days = int(os.getenv("WARN_AFTER_DAYS", "30"))
        terminate_after_days = int(os.getenv("TERMINATE_AFTER_DAYS", "60"))
        auto_terminate = os.getenv("AUTO_TERMINATE", "false").lower() == "true"
        max_termination_percent = int(os.getenv("MAX_TERMINATION_PERCENT", "50"))
        max_unknown_percent = int(os.getenv("MAX_UNKNOWN_PERCENT", "10"))
        target_regions = parse_target_regions(
            os.getenv("TARGET_REGIONS")
            or os.getenv("AWS_REGION")
            or os.getenv("AWS_DEFAULT_REGION", "")
        )

        if warn_after_days <= 0:
            raise ValueError("WARN_AFTER_DAYS must be positive")
        if terminate_after_days <= 0:
            raise ValueError("TERMINATE_AFTER_DAYS must be positive")
        if not 1 <= max_termination_percent <= 100:
            raise ValueError("MAX_TERMINATION_PERCENT must be between 1 and 100")
        if not 0 <= max_unknown_percent <= 100:
            raise ValueError("MAX_UNKNOWN_PERCENT must be between 0 and 100")
        if not target_regions:
            raise ValueError("TARGET_REGIONS must include at least one region")
        if warn_after_days > terminate_after_days:
            raise ValueError("WARN_AFTER_DAYS must be lower than or equal to TERMINATE_AFTER_DAYS")
        topic_region = topic_region_from_arn(sns_topic_arn)
        runtime_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        if runtime_region and topic_region != runtime_region:
            raise ValueError(
                f"SNS_TOPIC_ARN must use the Lambda region {runtime_region}, "
                f"not {topic_region}"
            )

        return cls(
            sns_topic_arn=sns_topic_arn,
            warn_after_days=warn_after_days,
            terminate_after_days=terminate_after_days,
            auto_terminate=auto_terminate,
            target_regions=target_regions,
            max_termination_percent=max_termination_percent,
            max_unknown_percent=max_unknown_percent,
        )


class AwsClientFactory:
    def __init__(self, boto3_module):
        self._boto3 = boto3_module
        self._cache: Dict[Tuple[str, str], object] = {}
        self._lock = Lock()
        self._client_config = (
            BotoConfig(retries={"mode": "adaptive", "max_attempts": MAX_API_ATTEMPTS})
            if BotoConfig is not None
            else None
        )

    def __call__(self, service_name: str, region_name: str):
        cache_key = (service_name, region_name)
        with self._lock:
            if cache_key not in self._cache:
                client_kwargs = {"region_name": region_name}
                if self._client_config is not None:
                    client_kwargs["config"] = self._client_config
                self._cache[cache_key] = self._boto3.client(
                    service_name,
                    **client_kwargs,
                )
            return self._cache[cache_key]


def lambda_handler(event, context):
    if event.get("ResourceType") == CONFIG_VALIDATION_RESOURCE_TYPE:
        return handle_config_validation_request(event, context)

    del context
    if boto3 is None:
        raise RuntimeError("boto3 is required in the Lambda runtime")
    config = Config.from_env()
    client_factory = AwsClientFactory(boto3)

    sns_client = client_factory("sns", topic_region_from_arn(config.sns_topic_arn))
    now = datetime.now(timezone.utc)

    report = build_report(
        config=config,
        client_factory=client_factory,
        now=now,
    )

    circuit_breaker = None
    if config.auto_terminate:
        circuit_breaker = evaluate_circuit_breaker(report=report, config=config)
        if circuit_breaker is not None:
            LOGGER.error(
                "Circuit breaker tripped; skipping all terminations: %s",
                json.dumps(circuit_breaker),
            )

    notification_sent = publish_report(
        sns_client=sns_client,
        config=config,
        report=report,
        circuit_breaker=circuit_breaker,
    )

    termination_result = {"terminated_ids": [], "failed_requests": [], "aborted": []}
    if config.auto_terminate and report["terminate"] and circuit_breaker is None:
        termination_result = terminate_workspaces(client_factory, report["terminate"], now)

    result = {
        "summary": report["summary"],
        "warn_count": len(report["warn"]),
        "terminate_count": len(report["terminate"]),
        "skipped_count": len(report["skipped"]),
        "unknown_count": len(report["unknown"]),
        "regional_error_count": len(report["regional_errors"]),
        "terminated_ids": termination_result["terminated_ids"],
        "termination_failure_count": len(termination_result["failed_requests"]),
        "termination_failures": termination_result["failed_requests"],
        "termination_aborted_count": len(termination_result["aborted"]),
        "termination_aborted": termination_result["aborted"],
        "circuit_breaker_tripped": circuit_breaker is not None,
        "circuit_breaker": circuit_breaker,
        "auto_terminate": config.auto_terminate,
        "notification_sent": notification_sent,
    }
    LOGGER.info("Lifecycle evaluation finished: %s", json.dumps(result))
    return result


def handle_config_validation_request(event, context):
    status = "SUCCESS"
    reason = "Lifecycle configuration is valid"

    if event.get("RequestType") != "Delete":
        try:
            properties = event.get("ResourceProperties", {})
            warn_after_days = int(properties["WarningThresholdDays"])
            terminate_after_days = int(properties["TerminationThresholdDays"])
            if warn_after_days > terminate_after_days:
                raise ValueError(
                    "WarningThresholdDays must be lower than or equal to "
                    "TerminationThresholdDays"
                )
            stack_region = properties["StackRegion"]
            stack_partition = properties["StackPartition"]
            existing_topic_arn = properties.get("ExistingSnsTopicArn", "").strip()
            if existing_topic_arn:
                validate_sns_topic_arn(
                    existing_topic_arn,
                    expected_region=stack_region,
                    expected_partition=stack_partition,
                )

            target_regions = parse_target_regions(properties["TargetRegions"])
            if not target_regions:
                raise ValueError("TargetRegions must include at least one region")
            available_regions = get_available_workspaces_regions(stack_partition)
            unsupported_regions = [
                region for region in target_regions if region not in available_regions
            ]
            if unsupported_regions:
                raise ValueError(
                    "TargetRegions contains regions unsupported by Amazon WorkSpaces in "
                    f"partition {stack_partition}: {', '.join(unsupported_regions)}"
                )
        except Exception as error:
            # Catch everything: an unhandled exception here would skip the
            # CloudFormation response below and hang the stack operation until
            # the custom-resource timeout.
            LOGGER.exception("Lifecycle configuration validation failed")
            status = "FAILED"
            reason = str(error) or type(error).__name__

    send_cloudformation_response(
        event=event,
        context=context,
        status=status,
        reason=reason,
    )
    return {"status": status, "reason": reason}


def send_cloudformation_response(event, context, status: str, reason: str) -> None:
    response_body = json.dumps(
        {
            "Status": status,
            "Reason": f"{reason}. Log stream: {getattr(context, 'log_stream_name', 'unknown')}",
            "PhysicalResourceId": event.get(
                "PhysicalResourceId",
                CONFIG_VALIDATION_PHYSICAL_RESOURCE_ID,
            ),
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": False,
            "Data": {},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        event["ResponseURL"],
        data=response_body,
        headers={
            "Content-Type": "",
            "Content-Length": str(len(response_body)),
        },
        method="PUT",
    )
    with urllib.request.urlopen(request, timeout=CFN_RESPONSE_TIMEOUT_SECONDS) as response:
        response.read()


def build_report(config: Config, client_factory, now: datetime) -> Dict[str, object]:
    evaluated_count = 0
    warn_items: List[Dict[str, object]] = []
    terminate_items: List[Dict[str, object]] = []
    skipped_items: List[Dict[str, object]] = []
    unknown_items: List[Dict[str, object]] = []
    regional_errors: List[Dict[str, str]] = []

    region_workers = min(MAX_REGION_SCAN_WORKERS, len(config.target_regions))
    with ThreadPoolExecutor(max_workers=region_workers) as executor:
        region_futures = [
            (
                region,
                executor.submit(
                    evaluate_region_workspaces,
                    region=region,
                    config=config,
                    client_factory=client_factory,
                    now=now,
                ),
            )
            for region in config.target_regions
        ]

        for region, future in region_futures:
            try:
                region_workspaces = future.result()
            except Exception as error:  # pragma: no cover - exercised via fake clients
                LOGGER.exception("Failed to evaluate WorkSpaces in region %s", region)
                regional_errors.append({"region": region, "reason": str(error)})
                continue

            for workspace in region_workspaces:
                evaluated_count += 1
                if workspace["status"] == "warn":
                    warn_items.append(workspace)
                elif workspace["status"] == "terminate":
                    terminate_items.append(workspace)
                elif workspace["status"] == "skipped":
                    skipped_items.append(workspace)
                elif workspace["status"] == "unknown":
                    unknown_items.append(workspace)

    warn_items.sort(key=lambda item: (-item["inactive_days"], item["region"], item["workspace_id"]))
    terminate_items.sort(key=lambda item: (-item["inactive_days"], item["region"], item["workspace_id"]))
    skipped_items.sort(key=lambda item: (item["region"], item["workspace_id"]))
    unknown_items.sort(key=lambda item: (item["region"], item["workspace_id"]))
    regional_errors.sort(key=lambda item: item["region"])

    summary = {
        "evaluated": evaluated_count,
        "warn": len(warn_items),
        "terminate": len(terminate_items),
        "skipped": len(skipped_items),
        "unknown": len(unknown_items),
        "regional_errors": len(regional_errors),
        "warn_after_days": config.warn_after_days,
        "terminate_after_days": config.terminate_after_days,
        "regions": list(config.target_regions),
        "generated_at": now.isoformat(),
    }

    return {
        "summary": summary,
        "warn": warn_items,
        "terminate": terminate_items,
        "skipped": skipped_items,
        "unknown": unknown_items,
        "regional_errors": regional_errors,
    }


def evaluate_region_workspaces(
    region: str,
    config: Config,
    client_factory,
    now: datetime,
) -> List[Dict[str, object]]:
    workspaces_client = client_factory("workspaces", region)
    ec2_client = client_factory("ec2", region)

    workspaces = list_workspaces(workspaces_client, region)
    if not workspaces:
        return []

    # Standby WorkSpaces (Multi-Region Resilience) are idle by design; users only
    # connect to them during a failover, so inactivity analysis does not apply.
    standby_items = [
        build_standby_skipped_item(workspace)
        for workspace in workspaces
        if workspace_is_standby(workspace)
    ]
    workspaces = [
        workspace for workspace in workspaces if not workspace_is_standby(workspace)
    ]
    if not workspaces:
        return standby_items

    eni_details_by_workspace_id = find_workspace_network_interfaces(
        ec2_client=ec2_client,
        workspaces=workspaces,
        now=now,
    )
    activity_workspace_ids = [
        workspace["WorkspaceId"]
        for workspace in workspaces
        if should_query_workspace_activity(
            eni_details=eni_details_by_workspace_id[workspace["WorkspaceId"]],
            warning_threshold_days=config.warn_after_days,
        )
    ]
    connection_status_by_workspace_id, status_errors_by_workspace_id = find_connection_statuses(
        workspaces_client=workspaces_client,
        workspace_ids=activity_workspace_ids,
    )

    classified_workspaces = [
        classify_workspace(
            workspace=workspace,
            now=now,
            warn_after_days=config.warn_after_days,
            terminate_after_days=config.terminate_after_days,
            eni_details=eni_details_by_workspace_id[workspace["WorkspaceId"]],
            connection_status=connection_status_by_workspace_id.get(workspace["WorkspaceId"]),
            connection_status_error=status_errors_by_workspace_id.get(workspace["WorkspaceId"]),
        )
        for workspace in workspaces
    ]

    return standby_items + apply_workspace_tag_exclusions(
        workspaces_client=workspaces_client,
        workspaces=classified_workspaces,
    )


def workspace_is_standby(workspace: Dict[str, object]) -> bool:
    """A standby WorkSpace's RelatedWorkspaces contains its PRIMARY WorkSpace."""
    return any(
        related.get("Type") == "PRIMARY"
        for related in workspace.get("RelatedWorkspaces", [])
    )


def build_standby_skipped_item(workspace: Dict[str, object]) -> Dict[str, object]:
    return {
        "workspace_id": workspace["WorkspaceId"],
        "region": workspace["Region"],
        "user_name": workspace.get("UserName", ""),
        "directory_id": workspace.get("DirectoryId"),
        "subnet_id": workspace.get("SubnetId"),
        "state": workspace.get("State", "UNKNOWN"),
        "computer_name": workspace.get("ComputerName", ""),
        "ip_address": workspace.get("IpAddress"),
        "eni_id": None,
        "eni_attached_at": None,
        "workspace_age_days": None,
        "connection_state": None,
        "status": "skipped",
        "inactive_days": None,
        "last_connected_at": None,
        "reason": "Standby WorkSpace for multi-region resilience; idle by design",
    }


def list_workspaces(workspaces_client, region: str) -> List[Dict[str, object]]:
    paginator = workspaces_client.get_paginator("describe_workspaces")
    workspaces: List[Dict[str, object]] = []

    for page in paginator.paginate():
        for workspace in page.get("Workspaces", []):
            state = workspace.get("State", "UNKNOWN")
            if state in {"TERMINATED", "TERMINATING"}:
                continue
            workspaces.append({**workspace, "Region": region})

    return workspaces


def classify_workspace(
    workspace: Dict[str, object],
    now: datetime,
    warn_after_days: int,
    terminate_after_days: int,
    eni_details: Dict[str, object],
    connection_status: Optional[Dict[str, object]],
    connection_status_error: Optional[str],
) -> Dict[str, object]:
    workspace_id = workspace["WorkspaceId"]
    directory_id = workspace.get("DirectoryId")
    ip_address = workspace.get("IpAddress")
    subnet_id = workspace.get("SubnetId")
    connection_status = connection_status or {"connection_state": None, "last_connected_at": None}

    base_item = {
        "workspace_id": workspace_id,
        "region": workspace["Region"],
        "user_name": workspace.get("UserName", ""),
        "directory_id": directory_id,
        "subnet_id": subnet_id,
        "state": workspace.get("State", "UNKNOWN"),
        "computer_name": workspace.get("ComputerName", ""),
        "ip_address": ip_address,
        "eni_id": eni_details["eni_id"],
        "eni_attached_at": eni_details["eni_attached_at"],
        "workspace_age_days": eni_details["workspace_age_days"],
        "connection_state": connection_status["connection_state"],
    }

    if eni_details["reason"] is not None:
        return {
            **base_item,
            "status": "unknown",
            "inactive_days": None,
            "last_connected_at": None,
            "reason": eni_details["reason"],
        }

    if eni_details["workspace_age_days"] < warn_after_days:
        return {
            **base_item,
            "status": "healthy",
            "inactive_days": None,
            "last_connected_at": None,
            "reason": (
                f"Current WorkSpace incarnation age is {eni_details['workspace_age_days']} days, "
                f"below the {warn_after_days} day warning threshold"
            ),
        }

    if connection_status_error is not None:
        return {
            **base_item,
            "status": "unknown",
            "inactive_days": None,
            "last_connected_at": None,
            "reason": connection_status_error,
        }

    if connection_status["connection_state"] == CONNECTED_STATE:
        return {
            **base_item,
            "status": "healthy",
            "inactive_days": 0,
            "last_connected_at": None,
            "reason": "User is currently connected to the WorkSpace",
        }

    last_connected_at = connection_status["last_connected_at"]
    if last_connected_at is None:
        inactive_days = eni_details["workspace_age_days"]
        status = classify_inactivity(inactive_days, warn_after_days, terminate_after_days)
        return {
            **base_item,
            "status": status,
            "inactive_days": inactive_days,
            "last_connected_at": None,
            "reason": (
                "No known user connection exists for the current WorkSpace incarnation"
            ),
        }

    effective_last_connected_at = max(last_connected_at, eni_details["attach_time"])
    inactive_days = int((now - effective_last_connected_at).total_seconds() // 86400)
    status = classify_inactivity(inactive_days, warn_after_days, terminate_after_days)

    return {
        **base_item,
        "status": status,
        "inactive_days": inactive_days,
        "last_connected_at": last_connected_at.isoformat(),
        "reason": f"Last known user connection was {inactive_days} days ago",
    }


def should_query_workspace_activity(
    eni_details: Dict[str, object],
    warning_threshold_days: int,
) -> bool:
    return (
        eni_details["reason"] is None
        and eni_details["workspace_age_days"] is not None
        and eni_details["workspace_age_days"] >= warning_threshold_days
    )


def find_connection_statuses(
    workspaces_client,
    workspace_ids: Sequence[str],
) -> Tuple[Dict[str, Dict[str, object]], Dict[str, str]]:
    results: Dict[str, Dict[str, object]] = {}
    errors: Dict[str, str] = {}

    for batch in chunked(list(workspace_ids), MAX_CONNECTION_STATUS_IDS):
        try:
            statuses = fetch_connection_status_batch(workspaces_client, batch)
        except Exception as error:
            LOGGER.exception(
                "Failed to query connection status for a WorkSpaces batch containing %s items",
                len(batch),
            )
            for workspace_id in batch:
                errors[workspace_id] = (
                    "Failed to query WorkSpaces connection status safely: "
                    f"{type(error).__name__}: {error}"
                )
            continue

        for workspace_id in batch:
            status = statuses.get(workspace_id)
            if status is None:
                errors[workspace_id] = (
                    "WorkSpaces connection status response omitted the requested WorkSpace"
                )
                continue
            results[workspace_id] = status

    return results, errors


def fetch_connection_status_batch(
    workspaces_client,
    workspace_ids: Sequence[str],
) -> Dict[str, Dict[str, object]]:
    statuses: Dict[str, Dict[str, object]] = {}
    next_token = None

    while True:
        request = {"WorkspaceIds": list(workspace_ids)}
        if next_token:
            request["NextToken"] = next_token

        response = workspaces_client.describe_workspaces_connection_status(**request)
        for status in response.get("WorkspacesConnectionStatus", []):
            workspace_id = status.get("WorkspaceId")
            if not workspace_id:
                continue
            last_connected_at = status.get("LastKnownUserConnectionTimestamp")
            statuses[workspace_id] = {
                "connection_state": status.get("ConnectionState"),
                "last_connected_at": (
                    normalize_timestamp(last_connected_at)
                    if last_connected_at is not None
                    else None
                ),
            }

        next_token = response.get("NextToken")
        if not next_token:
            break

    return statuses


def find_workspace_network_interfaces(
    ec2_client,
    workspaces: Sequence[Dict[str, object]],
    now: datetime,
) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}
    error_details_by_key: Dict[Tuple[str, str], Dict[str, object]] = {}
    workspaces_by_key: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    private_ips_by_subnet: Dict[str, List[str]] = defaultdict(list)
    seen_private_ips_by_subnet: Dict[str, set] = defaultdict(set)

    for workspace in workspaces:
        workspace_id = workspace["WorkspaceId"]
        ip_address = workspace.get("IpAddress")
        subnet_id = workspace.get("SubnetId")

        if not ip_address:
            results[workspace_id] = unresolved_eni_details(
                "WorkSpace has no IP address, so its ENI could not be resolved"
            )
            continue
        if not subnet_id:
            results[workspace_id] = unresolved_eni_details(
                "WorkSpace has no subnet ID, so its ENI could not be resolved safely"
            )
            continue

        workspaces_by_key[(ip_address, subnet_id)].append(workspace_id)
        if ip_address not in seen_private_ips_by_subnet[subnet_id]:
            seen_private_ips_by_subnet[subnet_id].add(ip_address)
            private_ips_by_subnet[subnet_id].append(ip_address)

    interfaces_by_key: Dict[Tuple[str, str], Dict[str, object]] = {}
    for subnet_id, private_ips in private_ips_by_subnet.items():
        for private_ip_batch in chunked(private_ips, MAX_NETWORK_INTERFACE_FILTER_VALUES):
            batch_keys = [(private_ip, subnet_id) for private_ip in private_ip_batch]
            try:
                next_token = None
                while True:
                    request = {
                        "Filters": [
                            {
                                "Name": "subnet-id",
                                "Values": [subnet_id],
                            },
                            {
                                "Name": "addresses.private-ip-address",
                                "Values": list(private_ip_batch),
                            },
                            {
                                "Name": "description",
                                "Values": list(WORKSPACES_ENI_DESCRIPTION_FILTERS),
                            },
                        ]
                    }
                    if next_token:
                        request["NextToken"] = next_token

                    response = ec2_client.describe_network_interfaces(**request)
                    for interface in response.get("NetworkInterfaces", []):
                        candidate = build_eni_candidate(interface, now)
                        if candidate is None:
                            continue
                        for private_ip in interface_private_ips(interface):
                            key = (private_ip, interface.get("SubnetId"))
                            existing = interfaces_by_key.get(key)
                            if existing is None or candidate["attach_time"] > existing["attach_time"]:
                                interfaces_by_key[key] = candidate

                    next_token = response.get("NextToken")
                    if not next_token:
                        break
            except Exception as error:
                LOGGER.exception(
                    "Failed to query network interfaces for subnet %s and %s private IPs",
                    subnet_id,
                    len(private_ip_batch),
                )
                error_details = unresolved_eni_details(
                    "Failed to query WorkSpace ENIs safely: "
                    f"{type(error).__name__}: {error}"
                )
                for key in batch_keys:
                    error_details_by_key[key] = dict(error_details)
                continue

    for key, workspace_ids in workspaces_by_key.items():
        # A batch error outranks any candidate found on earlier pages of the same
        # failed batch: partially observed batches must not drive lifecycle actions.
        details = error_details_by_key.get(key) or interfaces_by_key.get(key) or unresolved_eni_details(
            "No attached WorkSpaces ENI matched the WorkSpace IP address and expected description prefix"
        )
        for workspace_id in workspace_ids:
            results[workspace_id] = dict(details)

    return results


def build_eni_candidate(interface: Dict[str, object], now: datetime) -> Optional[Dict[str, object]]:
    description = interface.get("Description", "").lower()
    attachment = interface.get("Attachment", {})
    attach_time = attachment.get("AttachTime")
    if WORKSPACES_ENI_DESCRIPTION_FRAGMENT not in description:
        return None
    if attachment.get("Status") not in {None, "attached"}:
        return None
    if attach_time is None:
        return None

    attach_time = normalize_timestamp(attach_time)
    workspace_age_days = max(0, int((now - attach_time).total_seconds() // 86400))

    return {
        "eni_id": interface.get("NetworkInterfaceId"),
        "eni_attached_at": attach_time.isoformat(),
        "attach_time": attach_time,
        "workspace_age_days": workspace_age_days,
        "reason": None,
    }


def unresolved_eni_details(reason: str) -> Dict[str, object]:
    return {
        "eni_id": None,
        "eni_attached_at": None,
        "attach_time": None,
        "workspace_age_days": None,
        "reason": reason,
    }


def interface_private_ips(interface: Dict[str, object]) -> List[str]:
    private_ips: List[str] = []
    primary_private_ip = interface.get("PrivateIpAddress")
    if primary_private_ip:
        private_ips.append(primary_private_ip)

    for private_ip_info in interface.get("PrivateIpAddresses", []):
        private_ip = private_ip_info.get("PrivateIpAddress")
        if private_ip and private_ip not in private_ips:
            private_ips.append(private_ip)

    return private_ips


def normalize_timestamp(timestamp: datetime) -> datetime:
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp


def classify_inactivity(inactive_days: int, warn_after_days: int, terminate_after_days: int) -> str:
    if inactive_days >= terminate_after_days:
        return "terminate"
    if inactive_days >= warn_after_days:
        return "warn"
    return "healthy"


def apply_workspace_tag_exclusions(workspaces_client, workspaces: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    filtered_workspaces: List[Dict[str, object]] = []
    actionable_workspace_ids = [
        workspace["workspace_id"]
        for workspace in workspaces
        if workspace["status"] in {"warn", "terminate", "unknown"}
    ]
    tagged_workspace_ids, tag_errors = find_skip_auto_delete_tags(
        workspaces_client,
        actionable_workspace_ids,
    )

    for workspace in workspaces:
        if workspace["status"] not in {"warn", "terminate", "unknown"}:
            filtered_workspaces.append(workspace)
            continue

        workspace_id = workspace["workspace_id"]
        error = tag_errors.get(workspace_id)
        if error is not None:
            LOGGER.error(
                "Failed to query tags for WorkSpace %s",
                workspace_id,
                exc_info=(type(error), error, error.__traceback__),
            )
            filtered_workspaces.append(
                {
                    **workspace,
                    "status": "unknown",
                    "inactive_days": None,
                    "reason": (
                        "Failed to query WorkSpace tags safely: "
                        f"{type(error).__name__}: {error}"
                    ),
                }
            )
            continue

        if workspace_id in tagged_workspace_ids:
            LOGGER.info(
                "Skipping WorkSpace %s because it is tagged with %s",
                workspace_id,
                SKIP_AUTO_DELETE_TAG_KEY,
            )
            filtered_workspaces.append(
                {
                    **workspace,
                    "status": "skipped",
                    "reason": f"Skipped by WorkSpace tag {SKIP_AUTO_DELETE_TAG_KEY}",
                }
            )
            continue

        filtered_workspaces.append(workspace)

    return filtered_workspaces


def find_skip_auto_delete_tags(
    workspaces_client,
    workspace_ids: Sequence[str],
) -> Tuple[set, Dict[str, Exception]]:
    if not workspace_ids:
        return set(), {}

    def query_tag(workspace_id):
        try:
            return workspace_id, workspace_has_skip_auto_delete_tag(
                workspaces_client,
                workspace_id,
            ), None
        except Exception as error:
            return workspace_id, False, error

    worker_count = min(MAX_TAG_LOOKUP_WORKERS, len(workspace_ids))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = executor.map(query_tag, workspace_ids)
        tagged_workspace_ids = set()
        errors = {}
        for workspace_id, has_skip_tag, error in results:
            if error is not None:
                errors[workspace_id] = error
            elif has_skip_tag:
                tagged_workspace_ids.add(workspace_id)

    return tagged_workspace_ids, errors


def workspace_has_skip_auto_delete_tag(workspaces_client, workspace_id: str) -> bool:
    response = workspaces_client.describe_tags(ResourceId=workspace_id) or {}
    return any(
        tag.get("Key") == SKIP_AUTO_DELETE_TAG_KEY
        for tag in response.get("TagList", [])
    )


def evaluate_circuit_breaker(report: Dict[str, object], config: Config) -> Optional[Dict[str, object]]:
    """Return trip details when this run cannot terminate safely, else None.

    The breaker only engages when at least one termination candidate could
    actually be acted on; with nothing to halt, a trip would only add an
    alarming "TERMINATION HALTED" banner to the report (regional scan errors
    are already reported in their own section). A regional scan error trips
    the breaker because the fleet denominator is incomplete. Per-WorkSpace
    evaluation failures also trip the breaker when they exceed
    MAX_UNKNOWN_PERCENT of the lifecycle-eligible fleet. Otherwise, the
    breaker trips when more than MAX_TERMINATION_PERCENT of the successfully
    assessed, lifecycle-eligible WorkSpaces are termination candidates. The
    termination percentage check is only applied when at least
    MIN_EVALUATED_FOR_PERCENT_CHECK WorkSpaces were successfully assessed,
    because percentages are not meaningful for very small fleets.
    """
    terminate_count = sum(
        1
        for item in report["terminate"]
        if item.get("state") in TERMINATABLE_STATES
    )
    if terminate_count == 0:
        return None

    evaluated_count = report["summary"]["evaluated"]
    skipped_count = len(report.get("skipped", []))
    unknown_count = len(report.get("unknown", []))
    lifecycle_eligible_count = max(evaluated_count - skipped_count, 0)
    assessable_count = max(lifecycle_eligible_count - unknown_count, 0)
    unknown_percentage_value = (
        unknown_count / lifecycle_eligible_count * 100
        if lifecycle_eligible_count
        else 0.0
    )
    unknown_percent = round(unknown_percentage_value, 1)
    regional_errors = report.get("regional_errors", [])
    if regional_errors:
        percent = round(terminate_count / assessable_count * 100, 1) if assessable_count else 0.0
        region_names = ", ".join(item["region"] for item in regional_errors)
        error_count = len(regional_errors)
        return {
            "trigger": "regional_scan_errors",
            "terminate_count": terminate_count,
            "evaluated_count": evaluated_count,
            "assessable_count": assessable_count,
            "percent": percent,
            "regional_error_count": error_count,
            "reasons": [
                f"{error_count} configured region{'s' if error_count != 1 else ''} could not "
                f"be evaluated ({region_names}), so the fleet scan is incomplete"
            ],
        }

    if unknown_percentage_value > config.max_unknown_percent:
        return {
            "trigger": "unknown_percentage",
            "terminate_count": terminate_count,
            "evaluated_count": evaluated_count,
            "lifecycle_eligible_count": lifecycle_eligible_count,
            "assessable_count": assessable_count,
            "unknown_count": unknown_count,
            "unknown_percent": unknown_percent,
            "max_unknown_percent": config.max_unknown_percent,
            "reasons": [
                f"{unknown_count} of the {lifecycle_eligible_count} lifecycle-eligible "
                f"WorkSpaces ({unknown_percent}%) could not be evaluated safely, exceeding "
                f"the maximum of {config.max_unknown_percent}% (MaxUnknownPercent)"
            ],
        }

    if assessable_count < MIN_EVALUATED_FOR_PERCENT_CHECK:
        return None

    termination_percentage_value = terminate_count / assessable_count * 100
    percent = round(termination_percentage_value, 1)
    if termination_percentage_value <= config.max_termination_percent:
        return None

    return {
        "trigger": "termination_percentage",
        "terminate_count": terminate_count,
        "evaluated_count": evaluated_count,
        "assessable_count": assessable_count,
        "percent": percent,
        "max_termination_percent": config.max_termination_percent,
        "reasons": [
            f"{percent}% of the {assessable_count} successfully assessed, lifecycle-eligible "
            f"WorkSpaces are termination candidates, exceeding the maximum of "
            f"{config.max_termination_percent}% (MaxTerminationPercent)"
        ],
    }


def publish_report(
    sns_client,
    config: Config,
    report: Dict[str, object],
    circuit_breaker: Optional[Dict[str, object]] = None,
) -> bool:
    if not has_report_items(report):
        LOGGER.info("No WorkSpaces matched the lifecycle policy; skipping SNS notification")
        return False

    sns_client.publish(
        TopicArn=config.sns_topic_arn,
        Subject=REPORT_SUBJECT,
        Message=format_report_message(report, config.auto_terminate, circuit_breaker),
    )
    return True


def has_report_items(report: Dict[str, object]) -> bool:
    return any(report[key] for key in ("warn", "terminate", "skipped", "unknown", "regional_errors"))


def format_report_message(
    report: Dict[str, object],
    auto_terminate: bool,
    circuit_breaker: Optional[Dict[str, object]] = None,
) -> str:
    summary = report["summary"]
    lines = ["WorkSpaces Lifecycle Manager Report Summary"]
    lines.append(f"Generated at: {format_generated_at(summary['generated_at'])}")
    lines.append(f"AutoTerminate={'true' if auto_terminate else 'false'}.")
    lines.append(f"Regions scanned: {', '.join(summary['regions'])}.")
    lines.append("")
    lines.append(
        f"Summary: {summary['evaluated']} evaluated, {summary['warn']} warn, "
        f"{summary['terminate']} terminate, {summary['skipped']} skipped, "
        f"{summary['unknown']} unknown, {summary['regional_errors']} region errors."
    )

    if circuit_breaker is not None:
        lines.append("")
        lines.append("*** AUTOMATIC TERMINATION HALTED: CIRCUIT BREAKER TRIPPED ***")
        lines.append("")
        trigger = circuit_breaker.get("trigger")
        if trigger == "regional_scan_errors":
            lines.append(
                f"This run identified {circuit_breaker['terminate_count']} termination candidates, "
                f"but {circuit_breaker['regional_error_count']} configured "
                f"region{'s' if circuit_breaker['regional_error_count'] != 1 else ''} could not "
                "be evaluated. The fleet scan is incomplete, so automatic termination cannot "
                "proceed safely:"
            )
        elif trigger == "unknown_percentage":
            lines.append(
                f"This run identified {circuit_breaker['terminate_count']} termination candidates, "
                f"but {circuit_breaker['unknown_count']} of "
                f"{circuit_breaker['lifecycle_eligible_count']} lifecycle-eligible WorkSpaces "
                f"({circuit_breaker['unknown_percent']}%) could not be evaluated safely:"
            )
        else:
            lines.append(
                f"This run identified {circuit_breaker['terminate_count']} termination candidates "
                f"out of {circuit_breaker['assessable_count']} successfully assessed, "
                f"lifecycle-eligible WorkSpaces "
                f"({circuit_breaker['percent']}%), which exceeds the configured safety limits:"
            )
        lines.extend(f"- {reason}" for reason in circuit_breaker["reasons"])
        lines.append("")
        if trigger == "regional_scan_errors":
            lines.append(
                "As a safety measure, NO WorkSpaces were terminated in this run. "
                "Review the regional errors and termination candidates listed below. Automatic "
                "termination can resume on a later run after every configured region is evaluated "
                "successfully, or the listed WorkSpaces can be reviewed and terminated manually."
            )
        elif trigger == "unknown_percentage":
            lines.append(
                "As a safety measure, NO WorkSpaces were terminated in this run. "
                "Review the WorkSpaces that could not be evaluated safely and the termination "
                "candidates listed below. Automatic termination can resume after evaluation "
                "visibility recovers, or after MaxUnknownPercent is deliberately adjusted."
            )
        else:
            lines.append(
                "As a safety measure, NO WorkSpaces were terminated in this run. "
                "Review the termination candidates listed below. If this volume of terminations "
                "is intended, raise the MaxTerminationPercent stack parameter and let the next "
                "scheduled run proceed, or terminate the WorkSpaces manually. If it is not "
                "intended, investigate before changing the limit."
            )

    warn_items = report.get("warn", [])
    terminate_items = report.get("terminate", [])
    skipped_items = report.get("skipped", [])
    unknown_items = report.get("unknown", [])
    regional_errors = report.get("regional_errors", [])

    if regional_errors:
        lines.append("")
        lines.append("The following regions could not be evaluated:")
        lines.extend(
            f"- {item['region']}: {item['reason']}"
            for item in regional_errors
        )

    if warn_items:
        lines.append("")
        lines.append(
            f"The following WorkSpaces have had no connection in "
            f"{format_days(summary['warn_after_days'])}:"
        )
        lines.append("")
        lines.extend(format_workspace_item(item) for item in warn_items)
        lines.append("")
        lines.append(
            f"If these WorkSpaces remain inactive for "
            f"{format_days(summary['terminate_after_days'])}, they will become "
            "termination candidates."
        )
        if auto_terminate:
            lines.append(
                "Eligible candidates may then be deleted automatically after the safety re-checks."
            )
        else:
            lines.append(
                "They will not be deleted automatically while AutoTerminate=false."
            )

    if terminate_items:
        lines.append("")
        if auto_terminate and circuit_breaker is not None:
            terminate_heading = (
                f"The following WorkSpaces have had no connection in "
                f"{format_days(summary['terminate_after_days'])} but were NOT terminated "
                f"because the circuit breaker tripped (see above):"
            )
        elif auto_terminate:
            terminate_heading = (
                f"The following WorkSpaces have had no connection in "
                f"{format_days(summary['terminate_after_days'])} and may be deleted automatically:"
            )
        else:
            terminate_heading = (
                f"The following WorkSpaces are termination candidates as they have had no connection in "
                f"{format_days(summary['terminate_after_days'])}:"
            )
        lines.append(terminate_heading)
        lines.append("")
        lines.extend(format_workspace_item(item) for item in terminate_items)
        if not auto_terminate:
            lines.append("")
            lines.append(
                "Note: To automatically delete eligible WorkSpaces on future runs, "
                "change the AutoTerminate stack parameter to true."
            )

    if skipped_items:
        lines.append("")
        lines.append("The following WorkSpaces were skipped and excluded from lifecycle actions:")
        lines.append("")
        lines.extend(
            f"{format_workspace_item(item)}: {item['reason']}"
            for item in skipped_items
        )

    if unknown_items:
        lines.append("")
        lines.append("The following WorkSpaces could not be evaluated safely:")
        lines.extend(
            f"- {item['region']}: {item['workspace_id']} ({item.get('user_name') or 'unknown user'}): {item['reason']}"
            for item in unknown_items
        )

    if not warn_items and not terminate_items and not skipped_items and not unknown_items and not regional_errors:
        lines.append("")
        lines.append("No WorkSpaces matched the lifecycle policy.")

    return "\n".join(lines)


def format_workspace_item(item: Dict[str, object]) -> str:
    prefix = f"{item['region']}: {item['workspace_id']}"
    if item.get("user_name"):
        return f"- {prefix} ({item['user_name']})"
    return f"- {prefix}"


def format_days(days: int) -> str:
    if days == 1:
        return "1 day"
    return f"{days} days"


def format_generated_at(timestamp: str) -> str:
    parsed_timestamp = datetime.fromisoformat(timestamp)
    return normalize_timestamp(parsed_timestamp).astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%MZ"
    )


def terminate_workspaces(
    client_factory,
    terminate_items: Sequence[Dict[str, object]],
    now: datetime,
) -> Dict[str, object]:
    eligible_by_region: Dict[str, List[str]] = defaultdict(list)
    aborted: List[Dict[str, str]] = []
    for item in terminate_items:
        if item["state"] not in TERMINATABLE_STATES:
            aborted.append(
                {
                    "region": item["region"],
                    "workspace_id": item["workspace_id"],
                    "reason": (
                        "Termination aborted; WorkSpace state "
                        f"{item['state']} is not terminatable"
                    ),
                }
            )
            continue
        eligible_by_region[item["region"]].append(item["workspace_id"])

    terminated_ids: List[str] = []
    failed_requests: List[Dict[str, str]] = []

    for region, workspace_ids in eligible_by_region.items():
        workspaces_client = client_factory("workspaces", region)
        confirmed_ids = recheck_termination_candidates(
            workspaces_client=workspaces_client,
            region=region,
            workspace_ids=workspace_ids,
            now=now,
            aborted=aborted,
        )
        for batch in chunked(confirmed_ids, 25):
            request = [{"WorkspaceId": workspace_id} for workspace_id in batch]
            try:
                response = workspaces_client.terminate_workspaces(
                    TerminateWorkspaceRequests=request
                ) or {}
            except Exception as error:
                LOGGER.exception("Failed to terminate WorkSpaces in region %s", region)
                failed_requests.extend(
                    {
                        "region": region,
                        "workspace_id": workspace_id,
                        "error_code": type(error).__name__,
                        "error_message": str(error),
                    }
                    for workspace_id in batch
                )
                continue

            failures_by_workspace_id = {
                item["WorkspaceId"]: item
                for item in response.get("FailedRequests", [])
                if item.get("WorkspaceId")
            }
            if failures_by_workspace_id:
                LOGGER.error(
                    "TerminateWorkspaces reported failures in region %s: %s",
                    region,
                    json.dumps(
                        [
                            {
                                "workspace_id": workspace_id,
                                "error_code": failure.get("ErrorCode", "UnknownError"),
                                "error_message": failure.get("ErrorMessage", ""),
                            }
                            for workspace_id, failure in failures_by_workspace_id.items()
                        ]
                    ),
                )

            for workspace_id in batch:
                failure = failures_by_workspace_id.get(workspace_id)
                if failure is not None:
                    failed_requests.append(
                        {
                            "region": region,
                            "workspace_id": workspace_id,
                            "error_code": failure.get("ErrorCode", "UnknownError"),
                            "error_message": failure.get("ErrorMessage", ""),
                        }
                    )
                    continue
                terminated_ids.append(f"{region}:{workspace_id}")

    return {
        "terminated_ids": terminated_ids,
        "failed_requests": failed_requests,
        "aborted": aborted,
    }


def recheck_termination_candidates(
    workspaces_client,
    region: str,
    workspace_ids: Sequence[str],
    now: datetime,
    aborted: List[Dict[str, str]],
) -> List[str]:
    aborted_before = len(aborted)
    states, state_errors = find_current_workspace_states(
        workspaces_client,
        workspace_ids,
    )
    state_confirmed_ids: List[str] = []

    for workspace_id in workspace_ids:
        error = state_errors.get(workspace_id)
        if error is not None:
            aborted.append(
                {
                    "region": region,
                    "workspace_id": workspace_id,
                    "reason": f"Termination aborted; WorkSpace state re-check failed: {error}",
                }
            )
            continue

        state = states[workspace_id]
        if state not in TERMINATABLE_STATES:
            aborted.append(
                {
                    "region": region,
                    "workspace_id": workspace_id,
                    "reason": (
                        f"Termination aborted; current WorkSpace state {state} "
                        "is not terminatable"
                    ),
                }
            )
            continue

        state_confirmed_ids.append(workspace_id)

    tagged_workspace_ids, tag_errors = find_skip_auto_delete_tags(
        workspaces_client,
        state_confirmed_ids,
    )
    tag_confirmed_ids: List[str] = []

    for workspace_id in state_confirmed_ids:
        error = tag_errors.get(workspace_id)
        if error is not None:
            LOGGER.error(
                "Failed to re-check tags before terminating WorkSpace %s",
                workspace_id,
                exc_info=(type(error), error, error.__traceback__),
            )
            aborted.append(
                {
                    "region": region,
                    "workspace_id": workspace_id,
                    "reason": (
                        "Termination aborted; WorkSpace tag re-check failed: "
                        f"{type(error).__name__}: {error}"
                    ),
                }
            )
            continue

        if workspace_id in tagged_workspace_ids:
            aborted.append(
                {
                    "region": region,
                    "workspace_id": workspace_id,
                    "reason": (
                        f"Termination aborted; WorkSpace is tagged with "
                        f"{SKIP_AUTO_DELETE_TAG_KEY}"
                    ),
                }
            )
            continue

        tag_confirmed_ids.append(workspace_id)

    statuses, errors = find_connection_statuses(
        workspaces_client,
        tag_confirmed_ids,
    )

    confirmed_ids: List[str] = []
    for workspace_id in tag_confirmed_ids:
        error = errors.get(workspace_id)
        if error is not None:
            aborted.append(
                {
                    "region": region,
                    "workspace_id": workspace_id,
                    "reason": f"Termination aborted; connection status re-check failed: {error}",
                }
            )
            continue

        status = statuses.get(workspace_id) or {
            "connection_state": None,
            "last_connected_at": None,
        }
        if status["connection_state"] == CONNECTED_STATE:
            aborted.append(
                {
                    "region": region,
                    "workspace_id": workspace_id,
                    "reason": "Termination aborted; user is currently connected",
                }
            )
            continue

        last_connected_at = status["last_connected_at"]
        if last_connected_at is not None and last_connected_at >= now:
            aborted.append(
                {
                    "region": region,
                    "workspace_id": workspace_id,
                    "reason": "Termination aborted; user connected after the lifecycle evaluation started",
                }
            )
            continue

        confirmed_ids.append(workspace_id)

    aborted_count = len(aborted) - aborted_before
    if aborted_count:
        LOGGER.info(
            "Aborted termination for %s WorkSpaces in region %s after connection status re-check",
            aborted_count,
            region,
        )
    return confirmed_ids


def find_current_workspace_states(
    workspaces_client,
    workspace_ids: Sequence[str],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    states: Dict[str, str] = {}
    errors: Dict[str, str] = {}

    for batch in chunked(list(workspace_ids), 25):
        try:
            response = workspaces_client.describe_workspaces(
                WorkspaceIds=list(batch)
            )
        except Exception as error:
            LOGGER.exception(
                "Failed to re-check state for a WorkSpaces batch containing %s items",
                len(batch),
            )
            for workspace_id in batch:
                errors[workspace_id] = f"{type(error).__name__}: {error}"
            continue

        batch_states = {
            workspace["WorkspaceId"]: workspace.get("State", "UNKNOWN")
            for workspace in response.get("Workspaces", [])
            if workspace.get("WorkspaceId")
        }
        for workspace_id in batch:
            state = batch_states.get(workspace_id)
            if state is None:
                errors[workspace_id] = (
                    "DescribeWorkspaces response omitted the requested WorkSpace"
                )
                continue
            states[workspace_id] = state

    return states, errors


def chunked(items: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def parse_target_regions(raw_regions: str) -> Tuple[str, ...]:
    regions: List[str] = []
    seen = set()
    for token in raw_regions.split(","):
        region = token.strip()
        if not region or region in seen:
            continue
        if REGION_NAME_PATTERN.fullmatch(region) is None:
            raise ValueError(f"Invalid AWS region name in TARGET_REGIONS: {region}")
        seen.add(region)
        regions.append(region)
    return tuple(regions)


def topic_region_from_arn(topic_arn: str) -> str:
    return validate_sns_topic_arn(topic_arn)["region"]


def validate_sns_topic_arn(
    topic_arn: str,
    expected_region: Optional[str] = None,
    expected_partition: Optional[str] = None,
) -> Dict[str, str]:
    arn_parts = topic_arn.split(":", 5)
    if len(arn_parts) != 6:
        raise ValueError("SNS topic ARN must contain six colon-delimited components")

    arn_prefix, partition, service, region, account_id, topic_name = arn_parts
    if (
        arn_prefix != "arn"
        or ARN_PARTITION_PATTERN.fullmatch(partition) is None
        or service != "sns"
        or REGION_NAME_PATTERN.fullmatch(region) is None
        or AWS_ACCOUNT_ID_PATTERN.fullmatch(account_id) is None
        or SNS_TOPIC_NAME_PATTERN.fullmatch(topic_name) is None
    ):
        raise ValueError("SNS topic ARN must be a complete Amazon SNS topic ARN")
    if expected_partition and partition != expected_partition:
        raise ValueError(
            f"ExistingSnsTopicArn must use stack partition {expected_partition}, "
            f"not {partition}"
        )
    if expected_region and region != expected_region:
        raise ValueError(
            f"ExistingSnsTopicArn must use stack region {expected_region}, not {region}"
        )

    return {
        "partition": partition,
        "region": region,
        "account_id": account_id,
        "topic_name": topic_name,
    }


def get_available_workspaces_regions(partition: str) -> set:
    if boto3 is None:
        raise RuntimeError("boto3 is required to validate WorkSpaces regions")
    try:
        regions = set(
            boto3.Session().get_available_regions(
                "workspaces",
                partition_name=partition,
            )
        )
    except Exception as error:
        raise RuntimeError(
            f"Failed to load the Amazon WorkSpaces region catalog: {error}"
        ) from error
    if not regions:
        raise ValueError(
            f"No Amazon WorkSpaces regions are available in partition {partition}"
        )
    return regions
