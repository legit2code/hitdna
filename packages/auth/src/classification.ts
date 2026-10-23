import { 
  SecurityClassificationCode, 
  SecurityClassificationRank, 
  CLASSIFICATION_CODE_TO_RANK, 
  CLASSIFICATION_RANK_TO_CODE,
  UnauthorizedAccessError
} from './types.ts';

/**
 * Resolves numeric rank for a given classification code or rank.
 */
export function getClassificationRank(classification: SecurityClassificationCode | SecurityClassificationRank): SecurityClassificationRank {
  if (typeof classification === 'number') {
    return classification;
  }
  const rank = CLASSIFICATION_CODE_TO_RANK[classification];
  if (rank === undefined) {
    throw new Error(`Unknown security classification code: ${classification}`);
  }
  return rank;
}

/**
 * Resolves code string for a given classification rank.
 */
export function getClassificationCode(rank: SecurityClassificationRank): SecurityClassificationCode {
  const code = CLASSIFICATION_RANK_TO_CODE[rank];
  if (!code) {
    throw new Error(`Unknown security classification rank: ${rank}`);
  }
  return code;
}

/**
 * Enforces monotonic security classification propagation (Architecture V2.0.1 Document 13):
 * output_classification >= max(input_classifications)
 */
export function computeDerivedClassification(
  inputClassifications: (SecurityClassificationCode | SecurityClassificationRank)[]
): SecurityClassificationRank {
  if (!inputClassifications.length) {
    return SecurityClassificationRank.PUBLIC_METADATA;
  }

  const maxRank = inputClassifications.reduce<SecurityClassificationRank>((max, curr) => {
    const rank = getClassificationRank(curr);
    return rank > max ? rank : max;
  }, SecurityClassificationRank.PUBLIC_METADATA);

  return maxRank;
}

/**
 * Validates whether an output classification satisfies the derivation inheritance invariant.
 */
export function validateClassificationDerivation(
  inputClassifications: (SecurityClassificationCode | SecurityClassificationRank)[],
  outputClassification: SecurityClassificationCode | SecurityClassificationRank,
  authorizedDeclassification: boolean = false
): boolean {
  const minRequiredRank = computeDerivedClassification(inputClassifications);
  const outputRank = getClassificationRank(outputClassification);

  if (outputRank < minRequiredRank && !authorizedDeclassification) {
    throw new UnauthorizedAccessError(
      `Classification derivation violation: derived output rank (${outputRank}: ${getClassificationCode(outputRank)}) cannot be lower than max input rank (${minRequiredRank}: ${getClassificationCode(minRequiredRank)}) without authorized declassification.`
    );
  }

  return true;
}
