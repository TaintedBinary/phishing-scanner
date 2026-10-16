"""ICP query command-line workflow."""
import os
from datetime import datetime

from ..config import load_icp_service_config
from ..integrations.icp import ICP4759API, ICPService, query_urls
from ..integrations.icp_cache import ICPRecordStore


def run_icp_query(input_value, args, base_dir):
    config = load_icp_service_config(args.providers_config)

    services = []
    if config.get('enabled', True):
        services.append(ICPService(
            base_url=config['base_url'],
            exe_path=config['exe_path'],
            auto_start=config['auto_start'],
            startup_timeout=config['startup_timeout'],
            request_timeout=config['request_timeout'],
        ))

    fallback_api = config.get('fallback_api', {})
    if fallback_api.get('enabled') and fallback_api.get('url') and fallback_api.get('api_key'):
        services.append(
            ICP4759API(
                api_url=fallback_api['url'],
                api_key=fallback_api['api_key'],
                request_timeout=fallback_api['request_timeout'],
            )
        )

    record_store = None
    cache_config = config.get('cache', {})
    if cache_config.get('enabled') and cache_config.get('path'):
        record_store = ICPRecordStore(cache_config['path'])

    try:
        results = query_urls(input_value, services, record_store=record_store)
        output_icp_results(results, args, base_dir)
    finally:
        stop_services(services)


def stop_services(services):
    for service in services:
        stop = getattr(service, 'stop', None)
        if callable(stop):
            stop()


def _pick_first_record(records):
    if not records:
        return {}
    return records[0] if isinstance(records[0], dict) else {}


def output_icp_results(results, args, base_dir):
    lines = [f"ICP 备案查询结果 (共 {len(results)} 个)", "=" * 60]
    for i, result in enumerate(results, 1):
        lines.append(f"\n[{i}] {result.get('url', '')}")
        lines.append(f"    域名: {result.get('domain', '')}")
        if result.get('error'):
            lines.append(f"    错误: {result['error']}")
            continue

        if not result.get('has_filing'):
            lines.append("    状态: 未查到备案信息")
            continue

        record = _pick_first_record(result.get('records', []))
        unit = record.get('unitName') or record.get('mainUnitName') or '无'
        service_licence = (
            record.get('serviceLicence') or record.get('siteLicense') or
            record.get('serviceLicense') or '无'
        )
        main_licence = record.get('mainLicence') or '无'
        update_time = record.get('updateRecordTime') or '无'
        lines.append(f"    主办单位: {unit}")
        lines.append(f"    网站备案号: {service_licence}")
        lines.append(f"    主体备案号: {main_licence}")
        lines.append(f"    更新时间: {update_time}")
        lines.append(f"    来源: {result.get('source', 'ICP_Query/MIIT')}")

    output = '\n'.join(lines)

    if args.output:
        try:
            output_dir = os.path.join(os.getcwd(), 'output')
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = os.path.join(output_dir, f"icp_results_{timestamp}.txt")
            with open(filepath, 'w', encoding='utf-8') as handle:
                handle.write(output)
            print(f"结果已保存到 {filepath}")
        except Exception as exc:
            print(f"错误: 保存文件失败 - {exc}")
    else:
        print(output)
