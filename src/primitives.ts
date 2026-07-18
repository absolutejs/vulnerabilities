import { Type } from "@sinclair/typebox";

export const ISO_TIMESTAMP_PATTERN =
  "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})$";

export const TimestampSchema = Type.String({ pattern: ISO_TIMESTAMP_PATTERN });
export const IdentifierSchema = Type.String({ minLength: 1 });
export const NullableTimestampSchema = Type.Union([
  Type.Null(),
  TimestampSchema,
]);
