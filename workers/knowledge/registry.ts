import { 
  KnowledgeObject, 
  KnowledgeObjectType 
} from './types.ts';
import { SecurityClassificationCode } from '@caim/auth/types.ts';

export class KnowledgeObjectRegistry {
  private objects: Map<string, KnowledgeObject> = new Map();
  private entityRefMap: Map<string, string> = new Map();

  public registerObject(params: {
    entity_ref_id: string;
    object_type: KnowledgeObjectType;
    agent_id?: string | null;
    agent_version_id?: string | null;
    analysis_run_id?: string | null;
    security_classification_code: SecurityClassificationCode;
    security_classification_id?: string;
    projection_version?: string;
    source_data_hash: string;
  }): KnowledgeObject {
    const existingId = this.entityRefMap.get(params.entity_ref_id);
    const knowledge_object_id = existingId || `kobj-${params.entity_ref_id}`;

    const obj: KnowledgeObject = {
      knowledge_object_id,
      entity_ref_id: params.entity_ref_id,
      object_type: params.object_type,
      agent_id: params.agent_id ?? null,
      agent_version_id: params.agent_version_id ?? null,
      analysis_run_id: params.analysis_run_id ?? null,
      security_classification_id: params.security_classification_id || `sec-${params.security_classification_code.toLowerCase()}`,
      security_classification_code: params.security_classification_code,
      projection_version: params.projection_version || 'proj-2026.08.v1',
      source_data_hash: params.source_data_hash,
      created_at: this.objects.get(knowledge_object_id)?.created_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.objects.set(knowledge_object_id, obj);
    this.entityRefMap.set(params.entity_ref_id, knowledge_object_id);
    return obj;
  }

  public getObject(knowledgeObjectId: string): KnowledgeObject | undefined {
    return this.objects.get(knowledgeObjectId);
  }

  public getByEntityRefId(entityRefId: string): KnowledgeObject | undefined {
    const objId = this.entityRefMap.get(entityRefId);
    return objId ? this.objects.get(objId) : undefined;
  }

  public listObjects(filters?: {
    object_type?: KnowledgeObjectType;
    agent_id?: string;
    agent_version_id?: string;
  }): KnowledgeObject[] {
    let list = Array.from(this.objects.values());
    if (filters?.object_type) {
      list = list.filter((o) => o.object_type === filters.object_type);
    }
    if (filters?.agent_id) {
      list = list.filter((o) => o.agent_id === filters.agent_id);
    }
    if (filters?.agent_version_id) {
      list = list.filter((o) => o.agent_version_id === filters.agent_version_id);
    }
    return list;
  }

  public deleteByEntityRefId(entityRefId: string): boolean {
    const objId = this.entityRefMap.get(entityRefId);
    if (objId) {
      this.objects.delete(objId);
      this.entityRefMap.delete(entityRefId);
      return true;
    }
    return false;
  }

  public clear(): void {
    this.objects.clear();
    this.entityRefMap.clear();
  }

  public size(): number {
    return this.objects.size;
  }
}
