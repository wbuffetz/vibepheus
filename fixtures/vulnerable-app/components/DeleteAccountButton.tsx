'use client'
import { deleteMyAccount } from '@/lib/actions'

export default function DeleteAccountButton() {
  return <button onClick={() => deleteMyAccount()}>Delete my account</button>
}
