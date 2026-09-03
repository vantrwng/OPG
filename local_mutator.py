import asyncio
import aiohttp
import copy
import random

class FuzzDictionary:
    @staticmethod
    def get_mutations(value):
        if isinstance(value, int):
            return [-2147483648, 0, 9999999999, "abc", None]
        elif isinstance(value, float):
            return [-9999999.99, 0.0, "abc", None]
        elif isinstance(value, str):
            return ["", None, "A" * 5000, "' OR 1=1", "<script>alert(1)</script>", "../../../etc/passwd", "%00"]
        elif isinstance(value, list):
            return [[], None, value * 100]
        elif isinstance(value, dict):
            return [{}, None]
        elif isinstance(value, bool):
            return [not value, None, "true", 0]
        return [None, ""]

    @staticmethod
    def mutate_payload(payload, num_mutations=50):
        if not payload or not isinstance(payload, dict):
            return []
        
        mutated_payloads = []
        keys = list(payload.keys())
        
        if not keys:
            return []

        for _ in range(num_mutations):
            new_payload = copy.deepcopy(payload)
            key_to_mutate = random.choice(keys)
            original_val = new_payload[key_to_mutate]
            mutations = FuzzDictionary.get_mutations(original_val)
            new_payload[key_to_mutate] = random.choice(mutations)
            mutated_payloads.append(new_payload)
            
        return mutated_payloads

class AsyncFuzzEngine:
    @staticmethod
    async def blast_api(url, method, headers, valid_payload, num_requests=50,
                        query=None, cookies=None):
        """
        Gửi hàng loạt request bất đồng bộ để tìm lỗi 500.
        """
        payloads = FuzzDictionary.mutate_payload(valid_payload, num_requests)
        if not payloads:
            return []

        results = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for p in payloads:
                tasks.append(AsyncFuzzEngine._send_request(
                    session, url, method, headers, p,
                    query=dict(query or {}),
                    cookies=dict(cookies or {}),
                ))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for i, res in enumerate(responses):
                if isinstance(res, Exception):
                    results.append({
                        "status": 0,
                        "error": str(res),
                        "payload": payloads[i],
                        "transport_attempted": True,
                    })
                else:
                    results.append({
                        "status": res["status"],
                        "text": res["text"],
                        "payload": payloads[i],
                    })
        return results

    @staticmethod
    async def _send_request(session, url, method, headers, payload,
                            query=None, cookies=None):
        try:
            # Xóa Content-Length để aiohttp tự tính lại
            if headers and "Content-Length" in headers:
                headers = dict(headers)
                del headers["Content-Length"]

            method_name = method.upper()
            if method_name not in {"POST", "PUT", "PATCH", "DELETE"}:
                return {
                    "status": 0,
                    "text": "Unsupported method for body mutation",
                    "transport_attempted": False,
                }
            # Credentials are copied from one confirmed baseline. Passing them
            # per request avoids sharing a cookie jar between different actors.
            async with session.request(
                method_name,
                url,
                headers=dict(headers or {}),
                params=dict(query or {}),
                cookies=dict(cookies or {}),
                json=payload,
                timeout=5,
            ) as response:
                text = await response.text()
                return {
                    "status": response.status,
                    "text": text,
                    "transport_attempted": True,
                }
        except Exception as e:
            raise e
