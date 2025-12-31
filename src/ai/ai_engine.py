from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

MODEL_NAME = "fdtn-ai/Foundation-Sec-8B"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    torch_dtype=torch.float16,
    device_map="auto"
)

def analyze_incident(alert: str, ioc: str, log_snippet: str) -> str:
    prompt = f"""
You are a cybersecurity incident response assistant.
Analyze this incident with alert, IOC, and log snippet, and provide:
1) Summary
2) Classification
3) Severity
4) Response steps

Alert: {alert}
IOC: {ioc}
Log snippet: {log_snippet}

Produce a clear structured text result.
"""
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    outputs = model.generate(
        **inputs,
        max_new_tokens=350,
        temperature=0.3,
        top_p=0.9
    )
    return tokenizer.decode(outputs[0], skip_special_tokens=True)
