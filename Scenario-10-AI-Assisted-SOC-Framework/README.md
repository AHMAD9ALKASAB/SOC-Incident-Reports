# 🧠 AI-Assisted SOC Framework: The Tri-Agent Detection Engineering Pipeline

> "AI will not replace analysts. It will replace analysts who don't know how to audit AI."

## 📌 Executive Summary
As Large Language Models (LLMs) become integral to Security Operations Centers (SOCs), the risk of AI Hallucinations (fabricating scenarios, inventing IOCs, or missing ground truth) poses a critical threat. 

This repository documents a novel Tri-Agent Framework for AI-assisted Detection Engineering. It demonstrates how to take a raw threat scenario, force the AI to analyze it, aggressively audit its own output for hallucinations, and finally refine it into Production-Ready (10/10) detection rules. 

## 🏗️ The Tri-Agent Pipeline Architecture

This workflow uses three distinct "Personas" (Prompts) to simulate a real-world engineering team:

1. **The Analyst (prompts/analyst_master_prompt.md):** Generates the initial threat decomposition, IOCs, and baseline Sigma/SPL rules.
2. **The Auditor (prompts/auditor_master_prompt.md):** A ruthless Principal SOC Auditor that hunts for hallucinations, context bleeding, and evasion bypasses. (Spoiler: It gave the initial r1/10**1/10**).
3. **The Refiner (refiner_master_prompt.md):** A Senior Detection Engineer that synthesizes the ground truth and the auditor's critique to produce hardened, performance-optimized, and Production-Ready rules.

## ⚔️ The Case Study: Pass-the-Hash (NTLM) via PSEXEC
To prove the framework's effectiveness, we ran a live tPass-the-Hash (T1550.002)T1550.002)** scenario (PSEXEC lateral movement to a Domain ControPhase 1 (The Hallucination):cination):** The Analyst AI completely ignored the NTLM scenario, got stuck on a previous PowerShell context, and fabricated a fake C2 dPhase 2 (The Audit):he Audit):** The Auditor AI caught the hallucination, shredded the initial report (1/10), and mapped the actual MITRE techPhase 3 (The Refinement):finement):** The Refiner AI produced flawless, regex-resilient Sigma rules and optimized Splunk SPL queries (avoiding index=* and join bottleRead the full Battle Log here: Log here:** [evaluations/tri_agent_case_study.md](evaluations/tri_agent_case_study.md)

## 🚀 Deliverables (Production-Ready)
The repository contains the final, hardened artifacts extracted from this exercise. They are ready to be deployed in an enterprisSigma Rules:gma Rules:** Resilient to evasion techniques (renamed binaries, random service Splunk SPL:plunk SPL:** Optimized using stats instead of heavy join commands, and isolated to specific indexes.

## 🧠 Core Philosophy: "Code Intuition" (فراسة الكود)
True Detection Engineering is not about accepting what the AI generates. It is about treating the AI as a junior analyst that needs strict oversight. By establishing a fGeneration, Auditing, and RefinementRefinement**, SOC teams can leverage the speed of AI without compromising the integrity and security of their defense systems.

---
*Created by Ahmad Alqassab - SOC Analyst & Code Profiler*
