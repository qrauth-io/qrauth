import Anthropic from '@anthropic-ai/sdk';
import { PrismaClient } from '@prisma/client';
import { SYSTEM_PROMPT } from './prompts/system.js';
import { TOOL_DEFINITIONS, executeTool, cleanup } from './tools/index.js';

const prisma = new PrismaClient();

async function main() {
  const startTime = Date.now();
  console.log('[agent] Starting daily analysis...');

  // Create agent run record
  const agentRun = await prisma.agentRun.create({
    data: { runType: 'daily_analysis', status: 'running' },
  });

  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const messages: Anthropic.MessageParam[] = [
      {
        role: 'user',
        content: `Run your daily security and behavior analysis for the QRAuth platform. Today is ${new Date().toISOString().slice(0, 10)}.

Start by querying the last 24 hours of scan patterns and fraud incidents. Compare against the 7-day baseline. Then analyze login events and organization activity.

Look for:
1. New attack patterns not caught by existing rules
2. Unusual scan velocity or geographic patterns
3. Credential stuffing or account takeover attempts
4. Organizations with declining engagement (churn risk)
5. Any anomalies that warrant investigation

If you discover a clear pattern, create a fraud rule for it.
End by writing a daily security report with your findings.`,
      },
    ];

    let totalTokens = 0;
    let iterations = 0;
    const maxIterations = 15; // Safety limit

    while (iterations < maxIterations) {
      iterations++;
      console.log(`[agent] Iteration ${iterations}...`);

      const response = await client.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        tools: TOOL_DEFINITIONS as Anthropic.Tool[],
        messages,
      });

      totalTokens += (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0);

      // Process response
      const assistantContent = response.content;
      messages.push({ role: 'assistant', content: assistantContent });

      // Check if done
      if (response.stop_reason === 'end_turn') {
        // Extract final text
        const textBlocks = assistantContent.filter((b): b is Anthropic.TextBlock => b.type === 'text');
        const finalText = textBlocks.map((b) => b.text).join('\n');
        console.log('[agent] Analysis complete.');
        console.log(finalText);
        break;
      }

      // Process tool calls
      if (response.stop_reason === 'tool_use') {
        const toolResults: Anthropic.ToolResultBlockParam[] = [];

        for (const block of assistantContent) {
          if (block.type === 'tool_use') {
            console.log(`[agent] Calling tool: ${block.name}`);
            const result = await executeTool(block.name, block.input as Record<string, unknown>);
            toolResults.push({
              type: 'tool_result',
              tool_use_id: block.id,
              content: result,
            });
          }
        }

        messages.push({ role: 'user', content: toolResults });
      }
    }

    // Update agent run
    await prisma.agentRun.update({
      where: { id: agentRun.id },
      data: {
        status: 'completed',
        tokensUsed: totalTokens,
        durationMs: Date.now() - startTime,
        completedAt: new Date(),
        outputSummary: { iterations, totalTokens } as object,
      },
    });

    console.log(`[agent] Done. ${iterations} iterations, ${totalTokens} tokens, ${Date.now() - startTime}ms`);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('[agent] Failed:', message);
    await prisma.agentRun.update({
      where: { id: agentRun.id },
      data: { status: 'failed', error: message, completedAt: new Date(), durationMs: Date.now() - startTime },
    });
    process.exit(1);
  } finally {
    await cleanup();
    await prisma.$disconnect();
  }
}

main();
