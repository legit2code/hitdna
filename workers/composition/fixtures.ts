/**
 * Composition Fixture Scenarios for Testing and Diagnostics
 */

export interface CompositionFixtureScenario {
  id: string;
  name: string;
  description: string;
  expected_ecosystem: string;
  expected_direct_count: number;
  expected_transitive_count: number;
  expected_vuln_present: string[];
  expected_vuln_reachable: string[];
  expected_models: string[];
  expected_frameworks: string[];
  files: Record<string, string>;
}

export const COMPOSITION_FIXTURE_SCENARIOS: CompositionFixtureScenario[] = [
  {
    id: 'SCENARIO-01-PRESENT-VS-REACHABLE',
    name: 'Vulnerability Present (Unreached) vs Vulnerability Reachable',
    description: 'Demonstrates strict separation: lodash@4.17.20 is installed and zipObjectDeep is invoked (REACHABLE); axios@0.21.1 is installed but only imported without maxContentLength leak (PRESENT_UNREACHED).',
    expected_ecosystem: 'npm',
    expected_direct_count: 2,
    expected_transitive_count: 0,
    expected_vuln_present: ['CVE-2023-34462'],
    expected_vuln_reachable: ['CVE-2020-28500'],
    expected_models: ['gpt-4o', 'text-embedding-3-small'],
    expected_frameworks: ['langchain'],
    files: {
      'package.json': JSON.stringify({
        name: 'agent-reachability-demo',
        version: '1.0.0',
        dependencies: {
          'lodash': '4.17.20',
          'axios': '0.21.1'
        }
      }, null, 2),
      'src/main.ts': `
import { zipObjectDeep } from 'lodash';
import axios from 'axios';
import { ChatOpenAI } from 'langchain/chat_models/openai';

export function runAgentTask(keys: string[], values: any[]) {
  // Vulnerable function zipObjectDeep is directly called!
  const payload = zipObjectDeep(keys, values);

  // Model instantiation
  const model = new ChatOpenAI({ modelName: "gpt-4o", temperature: 0 });
  const embedder = "text-embedding-3-small";

  return { payload, model, embedder };
}
`
    }
  },
  {
    id: 'SCENARIO-02-PYTHON-AIBOM',
    name: 'Python AI Agent with AI-BOM & Jinja2 Template Injection',
    description: 'Python project using requirements.txt, HuggingFace transformer model card, and Jinja2 vulnerability.',
    expected_ecosystem: 'pypi',
    expected_direct_count: 3,
    expected_transitive_count: 0,
    expected_vuln_present: [],
    expected_vuln_reachable: ['CVE-2024-34064'],
    expected_models: ['meta-llama/Llama-3-8B', 'claude-3-5-sonnet'],
    expected_frameworks: ['transformers'],
    files: {
      'requirements.txt': `
jinja2==3.0.0
transformers>=4.30.0
torch==2.0.1
`,
      'agent.py': `
import jinja2
from transformers import AutoModelForCausalLM

system_prompt = """You are a helpful AI assistant. Answer queries concisely."""

def render_agent_template(user_input):
    # Calls vulnerable Jinja2 xmlattr/render path
    template = jinja2.Template("Hello {{ name }}")
    model_name = "meta-llama/Llama-3-8B"
    backup_model = "claude-3-5-sonnet"
    return template.render(name=user_input)
`
    }
  },
  {
    id: 'SCENARIO-03-UNREFERENCED-DEPENDENCY',
    name: 'Unreferenced Vulnerable Dependency in Manifest',
    description: 'Vulnerable Log4j is declared in dependencies, but no source file ever imports or references it.',
    expected_ecosystem: 'npm',
    expected_direct_count: 1,
    expected_transitive_count: 0,
    expected_vuln_present: ['CVE-2020-28500'],
    expected_vuln_reachable: [],
    expected_models: [],
    expected_frameworks: [],
    files: {
      'package.json': JSON.stringify({
        name: 'unreferenced-vuln-demo',
        version: '1.0.0',
        dependencies: {
          'lodash': '4.17.15'
        }
      }, null, 2),
      'src/index.ts': `
export function pureCalculation(a: number, b: number): number {
  // Lodash is never imported here
  return a + b;
}
`
    }
  }
];
