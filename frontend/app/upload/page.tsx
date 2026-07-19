import UploadDropzone from "@/components/UploadDropzone";

export default function UploadPage() {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-slate-100">Upload Sample</h1>
        <p className="text-slate-500 text-sm mt-1">
          SHA256 is calculated and checked against the full Case Knowledge Base before analysis begins.
        </p>
      </header>
      <UploadDropzone />
    </div>
  );
}
