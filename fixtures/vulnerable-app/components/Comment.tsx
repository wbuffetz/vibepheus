'use client'

export default function Comment({ comment }: { comment: { author: string; body: string } }) {
  return (
    <div className="comment">
      <strong>{comment.author}</strong>
      <div dangerouslySetInnerHTML={{ __html: comment.body }} />
    </div>
  )
}
