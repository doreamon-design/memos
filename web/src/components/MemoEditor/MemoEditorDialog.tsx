import { IconButton } from "@mui/joy";
import { useCallback, useEffect, useState } from "react";
import { useGlobalStore, useTagStore } from "@/store/module";
import { MemoRelation } from "@/types/proto/api/v2/memo_relation_service";
import MemoEditorV1 from ".";
import { generateDialog } from "../Dialog";
import Icon from "../Icon";

interface Props extends DialogProps {
  memoId?: number;
  cacheKey?: string;
  relationList?: MemoRelation[];
  //
  isFullscreen?: boolean;
  onFullscreenToggle?: () => void;
}

const MemoEditorDialog: React.FC<Props> = ({ memoId, cacheKey, relationList, destroy, isFullscreen, onFullscreenToggle }: Props) => {
  const globalStore = useGlobalStore();
  const tagStore = useTagStore();
  const { systemStatus } = globalStore.state;

  useEffect(() => {
    tagStore.fetchTags();
  }, []);

  const handleCloseBtnClick = () => {
    destroy();
  };

  return (
    <div
      className="memo-editor-dialog-wrapper w-full"
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <div className="w-full flex flex-row justify-between items-center mb-2">
        <div className="flex flex-row justify-start items-center">
          <img className="w-6 h-auto rounded-full shadow" src={systemStatus.customizedProfile.logoUrl} alt="" />
          <p className="ml-1 text-lg opacity-80 dark:text-gray-300">{systemStatus.customizedProfile.name}</p>
        </div>
        <div>
          <IconButton size="sm" onClick={onFullscreenToggle}>
            {isFullscreen ? <Icon.Minimize2 className="w-5 h-auto" /> : <Icon.Maximize2 className="w-5 h-auto" />}
          </IconButton>
          <IconButton size="sm" onClick={handleCloseBtnClick}>
            <Icon.X className="w-5 h-auto" />
          </IconButton>
        </div>
      </div>
      <div
        className="flex flex-col justify-start items-start max-w-full w-full"
        style={{
          flex: 1,
        }}
      >
        <MemoEditorV1
          className="border-none !p-0 -mb-2"
          style={{
            // minHeight: '60vh',
            flex: 1,
          }}
          editorStyle={{
            maxHeight: !isFullscreen ? 512 : 'calc(100vh - 200px)',
          }}
          cacheKey={`memo-editor-${cacheKey || memoId}`}
          memoId={memoId}
          relationList={relationList}
          onConfirm={handleCloseBtnClick}
          autoFocus
        />
      </div>
    </div>
  );
};

export default function showMemoEditorDialog(props: Pick<Props, "memoId" | "cacheKey" | "relationList"> = {}): void {
  generateDialog(
    {
      className: "memo-editor-dialog",
      dialogName: "memo-editor-dialog",
      containerClassName: "dark:!bg-zinc-800",
    },
    MemoEditorDialog,
    props,
  );
}
