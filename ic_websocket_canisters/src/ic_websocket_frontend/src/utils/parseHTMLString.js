export default function (HTMLstring) {
  const node = new DOMParser().parseFromString(HTMLstring, "text/html").body
    .firstElementChild;
  return node;
}
