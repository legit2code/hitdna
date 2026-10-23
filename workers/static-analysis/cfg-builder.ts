/**
 * Control Flow Graph (CFG) Generator
 * Authoritative AST-driven CFG construction with fallback to supplementary line scanning.
 * P15 — Static Analysis & Control Flow
 */

import ts from 'typescript';
import { ControlFlowGraph, CfgBasicBlock, CfgBlockTerminatorKind } from './types.ts';
import { SourceSpan } from '@caim/syntax/types.ts';

export class StaticCfgBuilder {
  /**
   * Generates a Control Flow Graph for a function or top-level code block using AST analysis
   */
  public static buildCfg(
    filePath: string,
    functionName: string,
    sourceContent: string,
    functionSpan?: SourceSpan
  ): ControlFlowGraph {
    const isJsTs = /\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(filePath);
    
    if (isJsTs && sourceContent) {
      try {
        const astCfg = this.buildJsTsAstCfg(filePath, functionName, sourceContent, functionSpan);
        if (astCfg) {
          return astCfg;
        }
      } catch {
        // Fall back to line scanning if AST traversal encounters unexpected error
      }
    }

    return this.buildFallbackLineScanningCfg(filePath, functionName, sourceContent, functionSpan);
  }

  /**
   * Authoritative CFG Construction using TypeScript Compiler API AST
   */
  private static buildJsTsAstCfg(
    filePath: string,
    functionName: string,
    sourceContent: string,
    functionSpan?: SourceSpan
  ): ControlFlowGraph | null {
    const scriptKind = filePath.endsWith('.tsx') ? ts.ScriptKind.TSX
      : filePath.endsWith('.jsx') ? ts.ScriptKind.JSX
      : filePath.endsWith('.js') ? ts.ScriptKind.JS
      : ts.ScriptKind.TS;

    const sourceFile = ts.createSourceFile(
      filePath,
      sourceContent,
      ts.ScriptTarget.Latest,
      true,
      scriptKind
    );

    // Find the target AST node (function or top-level sourceFile)
    let targetStatements: ts.NodeArray<ts.Statement> | ts.Statement[] | null = null;
    let targetStartLine = functionSpan?.start_line || 1;
    let targetFunctionNode: ts.Node | null = null;

    if (functionName === '<top-level>') {
      targetFunctionNode = sourceFile;
      targetStatements = sourceFile.statements;
      targetStartLine = 1;
    } else {
      // Find function/method/arrow function declaration matching functionName
      const findFunctionNode = (node: ts.Node): ts.Block | ts.NodeArray<ts.Statement> | null => {
        if (ts.isFunctionDeclaration(node) && node.name?.text === functionName && node.body) {
          targetFunctionNode = node;
          targetStartLine = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
          return node.body;
        }
        if (ts.isMethodDeclaration(node) && node.name?.getText(sourceFile) === functionName && node.body) {
          targetFunctionNode = node;
          targetStartLine = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
          return node.body;
        }
        if (ts.isConstructorDeclaration(node) && functionName === 'constructor' && node.body) {
          targetFunctionNode = node;
          targetStartLine = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
          return node.body;
        }
        if (ts.isVariableDeclaration(node) && node.name.getText(sourceFile) === functionName && node.initializer) {
          if (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) {
            if (ts.isBlock(node.initializer.body)) {
              targetFunctionNode = node.initializer;
              targetStartLine = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
              return node.initializer.body;
            }
          }
        }
        let found: ts.Block | ts.NodeArray<ts.Statement> | null = null;
        ts.forEachChild(node, child => {
          if (!found) {
            found = findFunctionNode(child);
          }
        });
        return found;
      };

      const fnBlock = findFunctionNode(sourceFile);
      if (fnBlock) {
        targetStatements = 'statements' in fnBlock ? (fnBlock as ts.Block).statements : Array.from(fnBlock);
      }
    }

    if (!targetStatements) {
      return null;
    }

    const cfgId = `cfg_${crypto.randomUUID().slice(0, 8)}`;
    const blocks: CfgBasicBlock[] = [];
    let cyclomaticComplexity = 1;
    let loopCount = 0;
    let exceptionHandlersCount = 0;
    let hasUnreachableBlocks = false;

    // Accurately compute cyclomatic complexity, loop count, and exception handlers across full AST subtree
    const countAstMetrics = (node: ts.Node) => {
      if (
        ts.isIfStatement(node) ||
        ts.isConditionalExpression(node) ||
        ts.isCaseClause(node)
      ) {
        cyclomaticComplexity++;
      } else if (
        ts.isForStatement(node) ||
        ts.isForOfStatement(node) ||
        ts.isForInStatement(node) ||
        ts.isWhileStatement(node) ||
        ts.isDoStatement(node)
      ) {
        cyclomaticComplexity++;
        loopCount++;
      } else if (ts.isCatchClause(node)) {
        cyclomaticComplexity++;
        exceptionHandlersCount++;
      } else if (ts.isBinaryExpression(node)) {
        if (
          node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
          node.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
        ) {
          cyclomaticComplexity++;
        }
      }
      ts.forEachChild(node, countAstMetrics);
    };

    if (targetFunctionNode && 'body' in targetFunctionNode && (targetFunctionNode as any).body) {
      ts.forEachChild((targetFunctionNode as any).body, countAstMetrics);
    } else if (targetFunctionNode) {
      ts.forEachChild(targetFunctionNode, countAstMetrics);
    }

    // Entry block
    const entryBlockId = 'block_0_entry';
    blocks.push({
      block_id: entryBlockId,
      label: `ENTRY: ${functionName}`,
      statements: [],
      start_line: targetStartLine,
      end_line: targetStartLine,
      predecessor_ids: [],
      successor_ids: [],
      terminator_kind: 'NORMAL',
      is_entry: true,
      is_exit: false,
      is_dead_code: false,
    });

    let currentBlockId = entryBlockId;
    let blockCounter = 1;
    let isCurrentlyReachable = true;

    // Traverse AST statements
    for (let i = 0; i < targetStatements.length; i++) {
      const stmt = targetStatements[i];
      const startPos = sourceFile.getLineAndCharacterOfPosition(stmt.getStart(sourceFile));
      const endPos = sourceFile.getLineAndCharacterOfPosition(stmt.getEnd());
      const stmtStartLine = startPos.line + 1;
      const stmtEndLine = endPos.line + 1;
      const stmtText = stmt.getText(sourceFile).slice(0, 100).replace(/\n/g, ' ');

      // 1. If Statement
      if (ts.isIfStatement(stmt)) {
        const branchBlockId = `block_${blockCounter++}_if_branch`;
        const mergeBlockId = `block_${blockCounter++}_if_merge`;

        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(stmtText);
          currBlock.end_line = stmtEndLine;
          currBlock.terminator_kind = 'BRANCH';
          currBlock.successor_ids.push(branchBlockId, mergeBlockId);
        }

        blocks.push({
          block_id: branchBlockId,
          label: `THEN_BRANCH (L${stmtStartLine})`,
          statements: [stmt.thenStatement.getText(sourceFile).slice(0, 80).replace(/\n/g, ' ')],
          start_line: stmtStartLine,
          end_line: stmtEndLine,
          predecessor_ids: [currentBlockId],
          successor_ids: [mergeBlockId],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        blocks.push({
          block_id: mergeBlockId,
          label: `MERGE (L${stmtEndLine})`,
          statements: [],
          start_line: stmtEndLine,
          end_line: stmtEndLine,
          predecessor_ids: [currentBlockId, branchBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        currentBlockId = mergeBlockId;
        continue;
      }

      // 2. Loops (For, ForOf, ForIn, While, DoWhile)
      if (
        ts.isForStatement(stmt) ||
        ts.isForOfStatement(stmt) ||
        ts.isForInStatement(stmt) ||
        ts.isWhileStatement(stmt) ||
        ts.isDoStatement(stmt)
      ) {
        const headerBlockId = `block_${blockCounter++}_loop_header`;
        const bodyBlockId = `block_${blockCounter++}_loop_body`;
        const exitBlockId = `block_${blockCounter++}_loop_exit`;

        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.successor_ids.push(headerBlockId);
        }

        blocks.push({
          block_id: headerBlockId,
          label: `LOOP_HEADER (L${stmtStartLine})`,
          statements: [stmtText],
          start_line: stmtStartLine,
          end_line: stmtStartLine,
          predecessor_ids: [currentBlockId, bodyBlockId],
          successor_ids: [bodyBlockId, exitBlockId],
          terminator_kind: 'LOOP_HEADER',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        blocks.push({
          block_id: bodyBlockId,
          label: `LOOP_BODY (L${stmtStartLine})`,
          statements: [stmt.statement.getText(sourceFile).slice(0, 80).replace(/\n/g, ' ')],
          start_line: stmtStartLine,
          end_line: stmtEndLine,
          predecessor_ids: [headerBlockId],
          successor_ids: [headerBlockId],
          terminator_kind: 'LOOP_BACK',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        blocks.push({
          block_id: exitBlockId,
          label: `LOOP_EXIT (L${stmtEndLine})`,
          statements: [],
          start_line: stmtEndLine,
          end_line: stmtEndLine,
          predecessor_ids: [headerBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        currentBlockId = exitBlockId;
        continue;
      }

      // 3. Exception Handlers: Try / Catch / Finally
      if (ts.isTryStatement(stmt)) {
        const handlerBlockId = `block_${blockCounter++}_exc_handler`;
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.successor_ids.push(handlerBlockId);
        }

        blocks.push({
          block_id: handlerBlockId,
          label: `EXC_HANDLER (L${stmtStartLine})`,
          statements: [stmt.catchClause ? stmt.catchClause.getText(sourceFile).slice(0, 80).replace(/\n/g, ' ') : stmtText],
          start_line: stmtStartLine,
          end_line: stmtEndLine,
          predecessor_ids: [currentBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: false,
        });
        continue;
      }

      // 4. Return Statement
      if (ts.isReturnStatement(stmt)) {
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(stmtText);
          currBlock.end_line = stmtEndLine;
          currBlock.terminator_kind = 'RETURN';
          currBlock.is_exit = true;
        }

        if (i < targetStatements.length - 1) {
          hasUnreachableBlocks = true;
          isCurrentlyReachable = false;
          const deadBlockId = `block_${blockCounter++}_dead_code`;
          blocks.push({
            block_id: deadBlockId,
            label: `UNREACHABLE_DEAD_CODE (L${stmtEndLine + 1})`,
            statements: [targetStatements[i + 1].getText(sourceFile).slice(0, 80).replace(/\n/g, ' ')],
            start_line: stmtEndLine + 1,
            end_line: stmtEndLine + 1,
            predecessor_ids: [],
            successor_ids: [],
            terminator_kind: 'UNREACHABLE',
            is_entry: false,
            is_exit: false,
            is_dead_code: true,
          });
        }
        continue;
      }

      // 5. Throw Statement
      if (ts.isThrowStatement(stmt)) {
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(stmtText);
          currBlock.end_line = stmtEndLine;
          currBlock.terminator_kind = 'THROW';
          currBlock.is_exit = true;
        }
        continue;
      }

      // 6. Normal sequential statements
      const currBlock = blocks.find(b => b.block_id === currentBlockId);
      if (currBlock) {
        currBlock.statements.push(stmtText);
        currBlock.end_line = stmtEndLine;
      }
    }

    const exitBlocks = blocks.filter(b => b.is_exit || b.successor_ids.length === 0);
    const exitBlockIds = exitBlocks.map(b => b.block_id);
    if (exitBlockIds.length === 0 && blocks.length > 0) {
      blocks[blocks.length - 1].is_exit = true;
      exitBlockIds.push(blocks[blocks.length - 1].block_id);
    }

    return {
      cfg_id: cfgId,
      file_path: filePath,
      function_name: functionName,
      cyclomatic_complexity: cyclomaticComplexity,
      blocks,
      has_unreachable_blocks: hasUnreachableBlocks,
      loop_count: loopCount,
      exception_handlers_count: exceptionHandlersCount,
      entry_block_id: entryBlockId,
      exit_block_ids: exitBlockIds,
    };
  }

  /**
   * Supplementary line-scanning CFG fallback for non-JS/TS languages or syntax errors
   */
  private static buildFallbackLineScanningCfg(
    filePath: string,
    functionName: string,
    sourceContent: string,
    functionSpan?: SourceSpan
  ): ControlFlowGraph {
    const cfgId = `cfg_${crypto.randomUUID().slice(0, 8)}`;
    const rawCode = functionSpan?.text_slice || sourceContent;
    const lines = rawCode.split('\n');
    const startLine = functionSpan?.start_line || 1;

    const blocks: CfgBasicBlock[] = [];
    let cyclomaticComplexity = 1;
    let loopCount = 0;
    let exceptionHandlersCount = 0;
    let hasUnreachableBlocks = false;

    const entryBlockId = 'block_0_entry';
    blocks.push({
      block_id: entryBlockId,
      label: `ENTRY: ${functionName}`,
      statements: [],
      start_line: startLine,
      end_line: startLine,
      predecessor_ids: [],
      successor_ids: [],
      terminator_kind: 'NORMAL',
      is_entry: true,
      is_exit: false,
      is_dead_code: false,
    });

    let currentBlockId = entryBlockId;
    let blockCounter = 1;
    let isCurrentlyReachable = true;

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i].trim();
      const currentLineNum = startLine + i;

      if (!lineText || lineText.startsWith('//') || lineText.startsWith('#') || lineText.startsWith('/*')) {
        continue;
      }

      if (lineText.startsWith('if ') || lineText.startsWith('if(') || lineText.includes(' if ')) {
        cyclomaticComplexity++;
        const branchBlockId = `block_${blockCounter++}_if_branch`;
        const mergeBlockId = `block_${blockCounter++}_if_merge`;

        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(lineText);
          currBlock.end_line = currentLineNum;
          currBlock.terminator_kind = 'BRANCH';
          currBlock.successor_ids.push(branchBlockId, mergeBlockId);
        }

        blocks.push({
          block_id: branchBlockId,
          label: `THEN_BRANCH (L${currentLineNum})`,
          statements: [`// then block`],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId],
          successor_ids: [mergeBlockId],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        blocks.push({
          block_id: mergeBlockId,
          label: `MERGE (L${currentLineNum})`,
          statements: [],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId, branchBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        currentBlockId = mergeBlockId;
        continue;
      }

      if (
        lineText.startsWith('for ') || lineText.startsWith('for(') || 
        lineText.startsWith('while ') || lineText.startsWith('while(') ||
        lineText.startsWith('for {')
      ) {
        cyclomaticComplexity++;
        loopCount++;

        const headerBlockId = `block_${blockCounter++}_loop_header`;
        const bodyBlockId = `block_${blockCounter++}_loop_body`;
        const exitBlockId = `block_${blockCounter++}_loop_exit`;

        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.successor_ids.push(headerBlockId);
        }

        blocks.push({
          block_id: headerBlockId,
          label: `LOOP_HEADER (L${currentLineNum})`,
          statements: [lineText],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId, bodyBlockId],
          successor_ids: [bodyBlockId, exitBlockId],
          terminator_kind: 'LOOP_HEADER',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        blocks.push({
          block_id: bodyBlockId,
          label: `LOOP_BODY (L${currentLineNum})`,
          statements: [`// loop body`],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [headerBlockId],
          successor_ids: [headerBlockId],
          terminator_kind: 'LOOP_BACK',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        blocks.push({
          block_id: exitBlockId,
          label: `LOOP_EXIT (L${currentLineNum})`,
          statements: [],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [headerBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        currentBlockId = exitBlockId;
        continue;
      }

      if (lineText.startsWith('try ') || lineText.startsWith('try{') || lineText.startsWith('catch') || lineText.startsWith('except')) {
        exceptionHandlersCount++;
        cyclomaticComplexity++;

        const handlerBlockId = `block_${blockCounter++}_exc_handler`;
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.successor_ids.push(handlerBlockId);
        }

        blocks.push({
          block_id: handlerBlockId,
          label: `EXC_HANDLER (L${currentLineNum})`,
          statements: [lineText],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: false,
        });

        continue;
      }

      if (lineText.startsWith('return ') || lineText === 'return;' || lineText === 'return') {
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(lineText);
          currBlock.end_line = currentLineNum;
          currBlock.terminator_kind = 'RETURN';
          currBlock.is_exit = true;
        }

        if (i < lines.length - 1 && !lines[i + 1].trim().startsWith('}') && lines[i + 1].trim().length > 0) {
          hasUnreachableBlocks = true;
          isCurrentlyReachable = false;
          const deadBlockId = `block_${blockCounter++}_dead_code`;
          blocks.push({
            block_id: deadBlockId,
            label: `UNREACHABLE_DEAD_CODE (L${currentLineNum + 1})`,
            statements: [lines[i + 1].trim()],
            start_line: currentLineNum + 1,
            end_line: currentLineNum + 1,
            predecessor_ids: [],
            successor_ids: [],
            terminator_kind: 'UNREACHABLE',
            is_entry: false,
            is_exit: false,
            is_dead_code: true,
          });
        }
        continue;
      }

      if (lineText.startsWith('throw ') || lineText.startsWith('raise ')) {
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(lineText);
          currBlock.end_line = currentLineNum;
          currBlock.terminator_kind = 'THROW';
          currBlock.is_exit = true;
        }
        continue;
      }

      const currBlock = blocks.find(b => b.block_id === currentBlockId);
      if (currBlock) {
        currBlock.statements.push(lineText);
        currBlock.end_line = currentLineNum;
      }
    }

    const exitBlocks = blocks.filter(b => b.is_exit || b.successor_ids.length === 0);
    const exitBlockIds = exitBlocks.map(b => b.block_id);

    if (exitBlockIds.length === 0 && blocks.length > 0) {
      blocks[blocks.length - 1].is_exit = true;
      exitBlockIds.push(blocks[blocks.length - 1].block_id);
    }

    return {
      cfg_id: cfgId,
      file_path: filePath,
      function_name: functionName,
      cyclomatic_complexity: cyclomaticComplexity,
      blocks,
      has_unreachable_blocks: hasUnreachableBlocks,
      loop_count: loopCount,
      exception_handlers_count: exceptionHandlersCount,
      entry_block_id: entryBlockId,
      exit_block_ids: exitBlockIds,
    };
  }
}
