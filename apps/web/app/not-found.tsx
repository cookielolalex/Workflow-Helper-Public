import Link from "next/link";

export default function NotFound() {
  return (
    <div className="page-shell">
      <section className="panel empty-state">
        <strong>Session not found</strong>
        <p>The record may not exist in this API process or may not be authorized.</p>
        <Link href="/">Return to dashboard</Link>
      </section>
    </div>
  );
}
