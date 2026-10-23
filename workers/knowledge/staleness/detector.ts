import { 
  KnowledgeObject, 
  KnowledgeProjection, 
  StaleIndexReport 
} from '../types.ts';
import { CURRENT_PROJECTION_VERSION } from '../projections/builders.ts';

export class StaleIndexDetector {
  /**
   * Evaluates staleness across projections and registered knowledge objects.
   */
  public static evaluateStaleness(
    objects: KnowledgeObject[],
    projections: Map<string, KnowledgeProjection>,
    expectedProjectionVersion: string = CURRENT_PROJECTION_VERSION
  ): StaleIndexReport {
    const totalObjects = objects.length;
    const staleEntityRefIds: string[] = [];

    for (const obj of objects) {
      const proj = projections.get(obj.entity_ref_id);

      if (!proj) {
        // No projection exists yet -> considered unindexed / stale
        staleEntityRefIds.push(obj.entity_ref_id);
        continue;
      }

      // Check 1: Explicit stale flag
      if (proj.stale) {
        staleEntityRefIds.push(obj.entity_ref_id);
        continue;
      }

      // Check 2: Version mismatch
      if (proj.projection_version !== expectedProjectionVersion) {
        staleEntityRefIds.push(obj.entity_ref_id);
        continue;
      }

      // Check 3: Hash divergence between source data and projection payload
      if (obj.source_data_hash && proj.payload?._source_hash && obj.source_data_hash !== proj.payload._source_hash) {
        staleEntityRefIds.push(obj.entity_ref_id);
        continue;
      }
    }

    const staleCount = staleEntityRefIds.length;
    const freshCount = totalObjects - staleCount;
    const stalePercentage = totalObjects === 0 ? 0 : Number(((staleCount / totalObjects) * 100).toFixed(2));

    return {
      timestamp: new Date().toISOString(),
      total_objects: totalObjects,
      stale_objects_count: staleCount,
      fresh_objects_count: freshCount,
      stale_percentage: stalePercentage,
      stale_entity_ref_ids: staleEntityRefIds,
      reindex_recommended: staleCount > 0,
    };
  }
}
