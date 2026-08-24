type StatusCardProps = {
  label: string;
  value: number | string;
  detail: string;
  tone?: "neutral" | "good" | "warning";
};

export function StatusCard({ label, value, detail, tone = "neutral" }: StatusCardProps) {
  return (
    <article className={`status-card status-card--${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}
